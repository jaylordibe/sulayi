package browser

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// maxMessageBytes bounds one protocol message from the browser. The largest
// messages Sulayi receives are paused requests carrying a page's request body,
// and a page cannot make those larger than this without the connection being
// closed rather than the process growing without bound.
const maxMessageBytes = 32 << 20

// errClosed reports a call on a connection the browser has closed.
var errClosed = errors.New("the browser connection is closed")

// message is one DevTools protocol frame, in either direction.
type message struct {
	ID        int64           `json:"id,omitempty"`
	Method    string          `json:"method,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *protocolError  `json:"error,omitempty"`
}

type protocolError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *protocolError) Error() string {
	return fmt.Sprintf("browser protocol error %d: %s", e.Code, e.Message)
}

// event is a notification from the browser for one session.
type event struct {
	Method string
	Params json.RawMessage
}

// conn speaks the DevTools protocol over the pipe Chrome opens with
// --remote-debugging-pipe: NUL-terminated JSON messages, no network listener.
//
// Calls are matched to replies by id. Events are delivered per session to the
// channel registered for it; an event for a session nobody registered is
// dropped, which is what happens to the browser's own targets Sulayi never
// attached to.
type conn struct {
	w io.WriteCloser

	writeMu sync.Mutex

	mu       sync.Mutex
	next     int64
	pending  map[int64]chan message
	sessions map[string]chan event
	closed   bool
	done     chan struct{}
	err      error
}

func newConn(r io.Reader, w io.WriteCloser) *conn {
	c := &conn{
		w:        w,
		pending:  map[int64]chan message{},
		sessions: map[string]chan event{},
		done:     make(chan struct{}),
	}
	go c.read(r)
	return c
}

// read delivers replies and events until the pipe closes or a message is
// malformed or oversized. Either ends the connection: a peer that breaks the
// framing once cannot be trusted to frame anything after it.
func (c *conn) read(r io.Reader) {
	br := bufio.NewReaderSize(r, 64<<10)
	var err error
	for {
		var frame []byte
		frame, err = readFrame(br)
		if err != nil {
			break
		}
		var m message
		if err = json.Unmarshal(frame, &m); err != nil {
			err = fmt.Errorf("the browser sent a malformed message: %w", err)
			break
		}
		c.dispatch(m)
	}
	c.shutdown(err)
}

// readFrame reads one NUL-terminated message, refusing one larger than
// maxMessageBytes.
func readFrame(br *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := br.ReadSlice(0)
		buf = append(buf, chunk...)
		if len(buf) > maxMessageBytes {
			return nil, fmt.Errorf("the browser sent a message larger than %d bytes", maxMessageBytes)
		}
		switch {
		case err == nil:
			return buf[:len(buf)-1], nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return nil, err
		}
	}
}

func (c *conn) dispatch(m message) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if m.ID != 0 {
		if ch, ok := c.pending[m.ID]; ok {
			delete(c.pending, m.ID)
			ch <- m
		}
		return
	}
	ch, ok := c.sessions[m.SessionID]
	if !ok {
		return
	}
	select {
	case ch <- event{Method: m.Method, Params: m.Params}:
	default:
		// A session that stops draining its events must not stall every other
		// session's replies, so the event is dropped. A dropped paused request
		// stays paused until its page's visit times out and the tab is closed.
	}
}

func (c *conn) shutdown(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	if err == nil || errors.Is(err, io.EOF) {
		err = errClosed
	}
	c.err = err
	for id, ch := range c.pending {
		delete(c.pending, id)
		ch <- message{Error: &protocolError{Code: -1, Message: err.Error()}}
	}
	for id, ch := range c.sessions {
		delete(c.sessions, id)
		close(ch)
	}
	close(c.done)
}

// subscribe registers the event channel for a session. The buffer is large
// because a page's requests arrive in bursts while their relays are running.
func (c *conn) subscribe(session string) <-chan event {
	ch := make(chan event, 4096)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		close(ch)
		return ch
	}
	c.sessions[session] = ch
	return ch
}

func (c *conn) unsubscribe(session string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ch, ok := c.sessions[session]; ok {
		delete(c.sessions, session)
		close(ch)
	}
}

// call sends one command and waits for its reply, or for ctx.
func (c *conn) call(ctx context.Context, session, method string, params any, result any) error {
	raw, err := json.Marshal(params)
	if err != nil {
		return err
	}
	ch := make(chan message, 1)
	c.mu.Lock()
	if c.closed {
		err := c.err
		c.mu.Unlock()
		return err
	}
	c.next++
	id := c.next
	c.pending[id] = ch
	c.mu.Unlock()

	frame, err := json.Marshal(message{ID: id, Method: method, Params: raw, SessionID: session})
	if err != nil {
		c.forget(id)
		return err
	}
	c.writeMu.Lock()
	_, err = c.w.Write(append(frame, 0))
	c.writeMu.Unlock()
	if err != nil {
		c.forget(id)
		return fmt.Errorf("cannot write to the browser: %w", err)
	}

	select {
	case m := <-ch:
		if m.Error != nil {
			return m.Error
		}
		if result != nil && len(m.Result) > 0 {
			return json.Unmarshal(m.Result, result)
		}
		return nil
	case <-ctx.Done():
		c.forget(id)
		return ctx.Err()
	}
}

func (c *conn) forget(id int64) {
	c.mu.Lock()
	delete(c.pending, id)
	c.mu.Unlock()
}

func (c *conn) close() {
	_ = c.w.Close()
}
