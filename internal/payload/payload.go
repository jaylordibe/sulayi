// Package payload is the closed catalogue of every injection payload Sulayi
// sends, each with the impact class that decides which profiles may send it
// (ADR-0023).
//
// The catalogue is closed on purpose. A check cannot compose a payload of its
// own: the HTTP client recognises every non-inert payload here in an outgoing
// request and refuses it where the profile does not permit its class, so what a
// check says about its own request is never what decides. Destructive SQL,
// stacked queries and delays are not in the catalogue, so nothing can send them.
package payload

import (
	"encoding/json"
	"net/url"
	"strings"
)

// Class is a payload's impact on the target.
type Class string

const (
	// Inert payloads are only reflected or echoed: a marker, a header value,
	// an unresolvable host, a malformed value. Every profile may send them.
	Inert Class = "inert"
	// Evaluating payloads are computed by the target if it is vulnerable:
	// template arithmetic. They change nothing but the response.
	Evaluating Class = "evaluating"
	// QueryAltering payloads change a database query's logic if the target
	// is vulnerable: boolean SQL conditions, never a stacked or data-changing
	// statement. A vulnerable write statement reached by a GET may still store
	// a condition's value; that is why these need standard.
	QueryAltering Class = "query-altering"
)

// Payload is one catalogue entry.
type Payload struct {
	ID    string
	Class Class
	// Value is what is sent: appended to a baseline value for SQL, the whole
	// value otherwise.
	Value string
}

// SQL boolean pairs. Each pair differs only in whether its condition holds;
// two independent pairs per context are what confirmation requires.
var (
	SQLStringTrue1  = Payload{"sqli-string-true-1", QueryAltering, "' AND 'sulayi'='sulayi"}
	SQLStringFalse1 = Payload{"sqli-string-false-1", QueryAltering, "' AND 'sulayi'='sulayj"}
	SQLStringTrue2  = Payload{"sqli-string-true-2", QueryAltering, "' AND 'sul4y'='sul4y"}
	SQLStringFalse2 = Payload{"sqli-string-false-2", QueryAltering, "' AND 'sul4y'='sul5y"}
	SQLNumberTrue1  = Payload{"sqli-number-true-1", QueryAltering, " AND 7193=7193"}
	SQLNumberFalse1 = Payload{"sqli-number-false-1", QueryAltering, " AND 7193=7194"}
	SQLNumberTrue2  = Payload{"sqli-number-true-2", QueryAltering, " AND 3817=3817"}
	SQLNumberFalse2 = Payload{"sqli-number-false-2", QueryAltering, " AND 3817=3818"}
)

// XSSMarker breaks out of an attribute or text context into markup. Its tag
// name is unique, so finding it unencoded in a response is not a coincidence.
var XSSMarker = Payload{"xss-marker", Inert, `"'><sulayi-x7f3>`}

// XSSTag is the part of XSSMarker that proves markup injection.
const XSSTag = "<sulayi-x7f3>"

// SSTIProduct is 7*7919 and SSTIProduct2 is 7*7927. A template engine that
// evaluates both expressions of one syntax renders both; nothing else
// plausibly produces either, let alone both.
const (
	SSTIProduct  = "55433"
	SSTIProduct2 = "55489"
)

// Templates are expressions in the common engines' syntaxes, and
// TemplatesSecond the same syntaxes with the second product.
var Templates = []Payload{
	{"ssti-curly", Evaluating, "{{7*7919}}"},
	{"ssti-dollar", Evaluating, "${7*7919}"},
	{"ssti-hash", Evaluating, "#{7*7919}"},
	{"ssti-erb", Evaluating, "<%= 7*7919 %>"},
}

var TemplatesSecond = []Payload{
	{"ssti-curly-2", Evaluating, "{{7*7927}}"},
	{"ssti-dollar-2", Evaluating, "${7*7927}"},
	{"ssti-hash-2", Evaluating, "#{7*7927}"},
	{"ssti-erb-2", Evaluating, "<%= 7*7927 %>"},
}

// RedirectHost can never resolve: .invalid is reserved (RFC 6761), and
// redirects are never followed.
const RedirectHost = "sulayi-redirect.invalid"

// Redirects are an absolute and a scheme-relative target on RedirectHost.
var Redirects = []Payload{
	{"redirect-absolute", Inert, "https://" + RedirectHost + "/"},
	{"redirect-scheme-relative", Inert, "//" + RedirectHost + "/"},
}

// CORSOrigin is the Origin a cross-origin probe presents.
var CORSOrigin = Payload{"cors-origin", Inert, "https://sulayi-origin.invalid"}

// Malformed is a value built to fail parsing in common stacks, so an error
// handler that discloses internals shows itself.
var Malformed = Payload{"malformed", Inert, `sulayi'")`}

// All returns the whole catalogue.
func All() []Payload {
	out := []Payload{
		SQLStringTrue1, SQLStringFalse1, SQLStringTrue2, SQLStringFalse2,
		SQLNumberTrue1, SQLNumberFalse1, SQLNumberTrue2, SQLNumberFalse2,
		XSSMarker, CORSOrigin, Malformed,
	}
	out = append(out, Templates...)
	out = append(out, TemplatesSecond...)
	return append(out, Redirects...)
}

// Find returns the most impactful non-inert payload present in a request, in
// its decoded path, query, header values or body. Inert payloads are not
// reported: every profile may send them.
func Find(rawURL string, header map[string][]string, body []byte) (Payload, bool) {
	var texts []string
	add := func(t string) { texts = append(texts, decodings(t)...) }
	if u, err := url.Parse(rawURL); err == nil {
		add(u.EscapedPath())
		add(u.RawQuery)
		// ParseQuery returns what it could parse alongside an error; what it
		// parsed is what an application would decode too.
		q, _ := url.ParseQuery(u.RawQuery)
		for k, vs := range q {
			add(k)
			for _, v := range vs {
				add(v)
			}
		}
	} else {
		add(rawURL)
	}
	for _, vs := range header {
		for _, v := range vs {
			add(v)
		}
	}
	add(string(body))
	var doc any
	if json.Unmarshal(body, &doc) == nil {
		for _, str := range jsonStrings(doc) {
			add(str)
		}
	}

	var found Payload
	var ok bool
	for _, p := range All() {
		if p.Class == Inert {
			continue
		}
		for _, t := range texts {
			if strings.Contains(t, p.Value) {
				if !ok || rank(p.Class) > rank(found.Class) {
					found, ok = p, true
				}
				break
			}
		}
	}
	return found, ok
}

// decodings returns a text and each successive percent-decoding of it, so a
// payload encoded more than once is still recognised.
func decodings(t string) []string {
	out := []string{t}
	for i := 0; i < 3; i++ {
		d, err := url.QueryUnescape(t)
		if err != nil {
			d, err = url.PathUnescape(t)
		}
		if err != nil || d == t {
			break
		}
		out = append(out, d)
		t = d
	}
	return out
}

// jsonStrings flattens every string in a decoded JSON document.
func jsonStrings(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, jsonStrings(e)...)
		}
		return out
	case map[string]any:
		var out []string
		for k, e := range x {
			out = append(out, k)
			out = append(out, jsonStrings(e)...)
		}
		return out
	}
	return nil
}

func rank(c Class) int {
	switch c {
	case QueryAltering:
		return 2
	case Evaluating:
		return 1
	}
	return 0
}
