package jsonpointer

import "testing"

// An id is returned exactly as the application wrote it. A 64-bit id decoded
// as a float would address a different record.
func TestNumbersKeepTheirExactText(t *testing.T) {
	for body, want := range map[string]string{
		`{"id":9007199254740993}`:    "9007199254740993",
		`{"id":1234567890123456789}`: "1234567890123456789",
		`{"e":{"code":100}}`:         "",
		`{"id":"abc"}`:               "abc",
	} {
		ptr := "/id"
		if want == "" {
			ptr, want = "/e/code", "100"
		}
		if got, ok := String([]byte(body), ptr); !ok || got != want {
			t.Errorf("%s %s = %q, %v; want %q", body, ptr, got, ok, want)
		}
	}
}
