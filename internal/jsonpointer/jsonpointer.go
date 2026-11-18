// Package jsonpointer resolves JSON pointers into scalar values. It is the one
// implementation, shared by outcome classification and login flows.
package jsonpointer

import (
	"encoding/json"
	"strconv"
	"strings"
)

// String resolves a JSON pointer (RFC 6901) to a scalar rendered as a string.
// Only object traversal is supported, which is all an error code or a login
// token needs.
func String(body []byte, pointer string) (string, bool) {
	if !strings.HasPrefix(pointer, "/") {
		return "", false
	}
	var cur any
	if err := json.Unmarshal(body, &cur); err != nil {
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
	case float64:
		// Numeric error codes are common. Trimming trailing zeros here would
		// turn 100 into "1" and silently break every configured mapping.
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case bool:
		if v {
			return "true", true
		}
		return "false", true
	}
	return "", false
}
