package browser

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// peer is a fake browser on the other end of the pipe.
type peer struct {
	in  *bufio.Reader  // what Sulayi sent
	out io.WriteCloser // what the browser sends
}

func newPair(t *testing.T) (*conn, *peer) {
	t.Helper()
	toPeerR, toPeerW := io.Pipe()
	fromPeerR, fromPeerW := io.Pipe()
	c := newConn(fromPeerR, toPeerW)
	t.Cleanup(func() { c.close(); _ = fromPeerW.Close() })
	return c, &peer{in: bufio.NewReader(toPeerR), out: fromPeerW}
}

func (p *peer) next(t *testing.T) message {
	t.Helper()
	b, err := p.in.ReadBytes(0)
	if err != nil {
		t.Fatal(err)
	}
	var m message
	if err := json.Unmarshal(b[:len(b)-1], &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func (p *peer) send(t *testing.T, s string) {
	t.Helper()
	if _, err := p.out.Write(append([]byte(s), 0)); err != nil {
		t.Fatal(err)
	}
}

func TestRepliesAreMatchedToTheirCalls(t *testing.T) {
	c, p := newPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got := make(chan string, 1)
	go func() {
		var r struct{ V string }
		if err := c.call(ctx, "s1", "X.y", map[string]any{}, &r); err != nil {
			got <- "error: " + err.Error()
			return
		}
		got <- r.V
	}()
	m := p.next(t)
	if m.Method != "X.y" || m.SessionID != "s1" {
		t.Fatalf("sent %+v", m)
	}
	p.send(t, `{"id":999,"result":{"V":"wrong"}}`)
	p.send(t, `{"id":`+itoa(m.ID)+`,"result":{"V":"right"}}`)
	if v := <-got; v != "right" {
		t.Fatalf("reply = %q", v)
	}
}

func TestEventsGoOnlyToTheirSession(t *testing.T) {
	c, p := newPair(t)
	a := c.subscribe("a")
	p.send(t, `{"method":"Fetch.requestPaused","sessionId":"b","params":{}}`)
	p.send(t, `{"method":"Page.loadEventFired","sessionId":"a","params":{}}`)
	select {
	case ev := <-a:
		if ev.Method != "Page.loadEventFired" {
			t.Fatalf("session a received %s", ev.Method)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no event")
	}
}

func TestAMalformedMessageEndsTheConnection(t *testing.T) {
	c, p := newPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- c.call(ctx, "", "X.y", struct{}{}, nil) }()
	p.next(t)
	p.send(t, `{not json`)
	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "malformed") {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a pending call was not released")
	}
	if err := c.call(ctx, "", "X.z", struct{}{}, nil); err == nil {
		t.Fatal("a call on a closed connection succeeded")
	}
}

func TestAnOversizedMessageEndsTheConnection(t *testing.T) {
	c, p := newPair(t)
	go func() {
		big := `{"method":"x","params":{"p":"` + strings.Repeat("a", maxMessageBytes) + `"}}`
		_, _ = p.out.Write(append([]byte(big), 0))
	}()
	select {
	case <-c.done:
	case <-time.After(10 * time.Second):
		t.Fatal("an oversized message did not end the connection")
	}
	if c.err == nil || !strings.Contains(c.err.Error(), "larger than") {
		t.Fatalf("err = %v", c.err)
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// A browser that stops reading its pipe cannot hold Close: the request to
// close blocks, and the process is killed instead of waited for.
func TestCloseKillsABrowserThatStoppedReading(t *testing.T) {
	blockedR, blockedW := io.Pipe() // nobody ever reads blockedR
	defer func() { _ = blockedR.Close() }()
	fromR, fromW := io.Pipe()
	defer func() { _ = fromW.Close() }()
	sink, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var killed atomic.Bool
	b := &Browser{conn: newConn(fromR, blockedW), profile: t.TempDir(), sink: sink, exited: make(chan struct{}),
		kill: func() { killed.Store(true); _ = blockedR.Close() }}
	done := make(chan error, 1)
	go func() { done <- b.Close() }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("Close did not return while the browser was not reading")
	}
	if !killed.Load() {
		t.Error("the browser was not killed")
	}
}
