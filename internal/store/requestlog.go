package store

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// RequestLogFile is the run's request log: one JSON object per line, one line
// per request the assessment attempted, including the ones it refused.
const RequestLogFile = "requests.jsonl"

// RequestLogEntry is one line of the request log. Every value in it has already
// been redacted by the HTTP client.
type RequestLogEntry struct {
	Seq       int64     `json:"seq"`
	Time      time.Time `json:"time"`
	Method    string    `json:"method"`
	URL       string    `json:"url"`
	Identity  string    `json:"identity"`
	Cleanup   bool      `json:"cleanup,omitempty"`
	Outcome   string    `json:"outcome"`
	Reason    string    `json:"reason,omitempty"`
	Status    int       `json:"status,omitempty"`
	ElapsedMs int64     `json:"elapsedMs,omitempty"`
}

// LogRequest appends one entry to the request log, creating it owner-only on
// first use. The file is opened for append on every call and closed again, so
// each line is written whole and nothing is buffered that a crash would lose.
func (r *Run) LogRequest(e RequestLogEntry) error {
	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("store: cannot encode a request log entry: %w", err)
	}
	line = append(line, '\n')

	r.logMu.Lock()
	defer r.logMu.Unlock()
	f, err := os.OpenFile(r.Path(RequestLogFile), os.O_CREATE|os.O_APPEND|os.O_WRONLY, fileMode)
	if err != nil {
		return fmt.Errorf("store: cannot open the request log: %w", err)
	}
	if _, err := f.Write(line); err != nil {
		_ = f.Close()
		return fmt.Errorf("store: cannot write the request log: %w", err)
	}
	return f.Close()
}
