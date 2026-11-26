package payload

import (
	"net/url"
	"testing"
)

func TestFindRecognisesNonInertPayloadsWhereverTheyAre(t *testing.T) {
	cases := []struct {
		url    string
		header map[string][]string
		body   string
		want   Class
	}{
		{"http://h/x?id=" + url.QueryEscape("1"+SQLNumberTrue1.Value), nil, "", QueryAltering},
		{"http://h/x/" + url.PathEscape("1"+SQLStringFalse2.Value), nil, "", QueryAltering},
		{"http://h/x", map[string][]string{"X-Name": {Templates[1].Value}}, "", Evaluating},
		{"http://h/x", nil, `{"q":"` + Templates[0].Value + `"}`, Evaluating},
		{"http://h/x", nil, "q=" + url.QueryEscape(Templates[3].Value), Evaluating},
		// A query Go refuses to parse whole still has its other values decoded.
		{"http://h/x?a=1;b&id=" + url.QueryEscape("1"+SQLStringTrue1.Value), nil, "", QueryAltering},
		{"http://h/x?x=%zz&id=" + url.QueryEscape("1"+SQLStringTrue1.Value), nil, "", QueryAltering},
		// Encoded twice.
		{"http://h/x?id=" + url.QueryEscape(url.QueryEscape("1"+SQLNumberTrue2.Value)), nil, "", QueryAltering},
		// A JSON body escapes < and > as \u003c and \u003e.
		{"http://h/x", nil, `{"q":"\u003c%= 7*7919 %\u003e"}`, Evaluating},
	}
	for _, c := range cases {
		p, ok := Find(c.url, c.header, []byte(c.body))
		if !ok || p.Class != c.want {
			t.Errorf("%s %v %q: got %+v %v, want %s", c.url, c.header, c.body, p, ok, c.want)
		}
	}
	for _, u := range []string{
		"http://h/x?q=" + url.QueryEscape(XSSMarker.Value),
		"http://h/x?next=" + url.QueryEscape(Redirects[0].Value),
		"http://h/x?id=1",
	} {
		if p, ok := Find(u, nil, nil); ok {
			t.Errorf("%s reported %+v; inert and ordinary values are not gated", u, p)
		}
	}
}
