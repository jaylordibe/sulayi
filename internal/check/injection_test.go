package check

import (
	"testing"

	"github.com/jaylordibe/sulayi/internal/model"
)

func TestStackSignaturesMatchFramesNotNames(t *testing.T) {
	traces := map[string]string{
		"PHP":                    "Stack trace:\n#0 /var/www/app/Http/Controllers/X.php(42): foo()\n",
		"PHP (debug JSON trace)": `{"message":"x","trace":[{"file":"/var/www/vendor/a/b.php","line":1}]}`,
		"Node.js":                "Error: x\n    at parse (/app/src/a.js:12:9)\n",
		"Python":                 "Traceback (most recent call last):\n  File \"/app/x.py\", line 3\n",
		"Java":                   "java.lang.IllegalStateException: x\n\tat com.acme.X.run(X.java:10)\n",
		".NET":                   "System.Exception: x\n   at Acme.X.Run() in C:\\src\\X.cs:line 10\n",
	}
	for want, body := range traces {
		if got := stackSignature(body); got != want {
			t.Errorf("%s: got %q", want, got)
		}
	}
	for _, body := range []string{
		"Built with Laravel and Node.js",
		`{"message":"Invalid year","hint":"look at the docs"}`,
		"<p>Meet us at the office (Room 4.js:12:9)</p>",
	} {
		if got := stackSignature(body); got != "" {
			t.Errorf("%q matched %s", body, got)
		}
	}
}

func TestRawTextContexts(t *testing.T) {
	for before, want := range map[string]string{
		"<p>Results for ":                  "",
		"<script>var q = '":                "a <script> element",
		"<script></script><p>":             "",
		"<title>Search ":                   "a <title> element",
		"<!-- debug: ":                     "an HTML comment",
		"<textarea name=q>":                "a <textarea> element",
		"<style>.x{}</style><div class=a>": "",
	} {
		if got := rawTextContext(before); got != want {
			t.Errorf("%q: got %q want %q", before, got, want)
		}
	}
}

// An application that echoes its input escaped by its JSON encoder is not
// different for that reason.
func TestNormalisedRemovesEscapedEchoes(t *testing.T) {
	injected := "' AND 'sulayi'='sulayi"
	for _, echo := range []string{
		injected,
		`' AND 'sulayi'='sulayi`,
		`&#39; AND &#39;sulayi&#39;=&#39;sulayi`,
		`&apos; AND &apos;sulayi&apos;=&apos;sulayi`,
	} {
		resp := &model.CapturedResponse{Status: 200, Body: []byte(`{"q":"1` + echo + `","items":[]}`)}
		if got := normalised(resp, injected); got != `{"q":"1","items":[]}` {
			t.Errorf("echo %q normalised to %q", echo, got)
		}
	}
}
