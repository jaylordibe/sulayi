package discovery

import (
	"sort"
	"strings"
	"testing"

	"github.com/jaylordibe/sulayi/internal/model"
)

// harFixture is a browser recording carrying every kind of secret a real one
// does: a session cookie, a bearer token, a password in a body, an API key in
// a query string, and a reset token in a path.
const harFixture = `{"log":{"version":"1.2","entries":[
 {"request":{"method":"GET","url":"http://app.test/api/orders?page=2&api_key=QUERY-SECRET-123",
   "headers":[{"name":"Authorization","value":"Bearer HEADER-SECRET-456"},{"name":"Cookie","value":"sid=COOKIE-SECRET-789"}],
   "cookies":[{"name":"sid","value":"COOKIE-SECRET-789"}]},
  "response":{"status":200,"content":{"text":"{\"token\":\"RESPONSE-SECRET-000\"}"}}},
 {"request":{"method":"post","url":"http://app.test/api/auth/login",
   "postData":{"mimeType":"application/json","text":"{\"password\":\"BODY-SECRET-111\"}"}}},
 {"request":{"method":"GET","url":"http://app.test/api/orders/17"}},
 {"request":{"method":"DELETE","url":"http://app.test/api/orders/17"}},
 {"request":{"method":"GET","url":"http://app.test/reset/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"}},
 {"request":{"method":"GET","url":"http://app.test/verify/a8F3kQ9zLm2Xp7Rt5Vw1Yb6Nc4Hd0Je8Sg"}},
 {"request":{"method":"GET","url":"http://cdn.other.test/lib.js"}},
 {"request":{"method":"GET","url":"https://app.test/api/orders"}},
 {"request":{"method":"GET","url":"http://app.test/static/app.js"}},
 {"request":{"method":"OPTIONS","url":"http://app.test/api/orders"}},
 {"request":{"method":"GET","url":"http://app.test/api/../admin"}},
 {"request":{"method":"GET","url":"http://app.test/api/orders?page=3"}}
]}}`

func TestHARYieldsOperationsAndNothingElse(t *testing.T) {
	res, err := ParseHAR([]byte(harFixture), "http://app.test")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, op := range res.Operations {
		ids = append(ids, op.ID)
		if len(op.Sources) != 1 || op.Sources[0].Kind != model.SourceHAR {
			t.Errorf("%s does not record its HAR provenance: %+v", op.ID, op.Sources)
		}
		if op.Security != nil {
			t.Errorf("%s gained an expectation from a recording: %+v", op.ID, op.Security)
		}
	}
	want := "DELETE /api/orders/17,GET /api/orders,GET /api/orders/17,POST /api/auth/login"
	if got := strings.Join(sorted(ids), ","); got != want {
		t.Errorf("operations = %s\nwant         %s", got, want)
	}
	if res.OffOrigin != 2 || res.Assets != 1 || res.Sensitive != 2 || res.Skipped != 2 {
		t.Errorf("accounting = %+v", res)
	}

	// Nothing but method and path survives. Every secret the recording held is
	// absent from everything ParseHAR returned.
	dump := strings.Join(ids, " ")
	for _, op := range res.Operations {
		dump += op.PathTemplate + op.BaseURL
		for _, s := range op.Sources {
			dump += s.Ref
		}
	}
	for _, secret := range []string{"QUERY-SECRET", "HEADER-SECRET", "COOKIE-SECRET", "BODY-SECRET",
		"RESPONSE-SECRET", "eyJhbGci", "a8F3kQ9zLm2X", "page="} {
		if strings.Contains(dump, secret) {
			t.Errorf("%q survived HAR import", secret)
		}
	}
}

func TestHARRespectsTheTargetsBasePath(t *testing.T) {
	doc := `{"log":{"entries":[
	 {"request":{"method":"GET","url":"http://app.test/app/api/x"}},
	 {"request":{"method":"GET","url":"http://app.test/other/api/x"}}]}}`
	res, err := ParseHAR([]byte(doc), "http://app.test/app")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Operations) != 1 || res.Operations[0].AbsolutePath() != "/app/api/x" {
		t.Fatalf("operations = %+v", res.Operations)
	}
	if res.OffOrigin != 1 {
		t.Errorf("a path outside the base path was not left out: %+v", res)
	}
}

func TestMalformedHARIsRefusedWithoutEchoingIt(t *testing.T) {
	_, err := ParseHAR([]byte(`not json SECRET-IN-FILE`), "http://app.test")
	if err == nil || strings.Contains(err.Error(), "SECRET-IN-FILE") {
		t.Fatalf("err = %v", err)
	}
}

// A recorded request that matches an operation the surface already has
// corroborates it rather than duplicating it.
func TestMergeOperationsCorroboratesMatchingTemplates(t *testing.T) {
	existing := []model.Operation{{ID: "GET /api/orders/{id}", Method: "GET", PathTemplate: "/api/orders/{id}"}}
	found := []model.Operation{
		{ID: "GET /api/orders/17", Method: "GET", PathTemplate: "/api/orders/17",
			Sources: []model.Source{{Kind: model.SourceHAR}}},
		{ID: "DELETE /api/orders/17", Method: "DELETE", PathTemplate: "/api/orders/17"},
	}
	out, added, corroborated := MergeOperations(existing, found)
	if added != 1 || corroborated != 1 || len(out) != 2 {
		t.Fatalf("added %d corroborated %d out %d", added, corroborated, len(out))
	}
	for _, op := range out {
		if op.ID == "GET /api/orders/{id}" && len(op.Sources) != 1 {
			t.Errorf("the corroborating source was not recorded: %+v", op.Sources)
		}
	}
}

func sorted(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}
