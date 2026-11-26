// Package jsonpointer resolves JSON pointers into scalar values. It is the one
// implementation, shared by outcome classification and login flows.
package jsonpointer

import (
	"bytes"
	"encoding/json"
	"strings"
)

// String resolves a JSON pointer (RFC 6901) to a scalar rendered as a string.
// Only object traversal is supported, which is all an error code or a login
// token needs.
func String(body []byte, pointer string) (string, bool) {
	if !strings.HasPrefix(pointer, "/") {
		return "", false
	}
	// Numbers are kept as their literal text. Decoding them as float64 would
	// round an id above 2^53 into a different id, and a request addressed by
	// it would reach a different record.
	var cur any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&cur); err != nil {
		return "", false
	}
	for _, rawToken := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		token := strings.ReplaceAll(strings.ReplaceAll(rawToken, "~1", "/"), "~0", "~")
		obj, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		cur, ok = obj[token]
		if !ok {
			return "", false
		}
	}
	switch v := cur.(type) {
	case string:
		return v, true
	case json.Number:
		return v.String(), true
	case bool:
		if v {
			return "true", true
		}
		return "false", true
	}
	return "", false
}
