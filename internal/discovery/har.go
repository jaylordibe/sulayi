package discovery

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/jaylordibe/sulayi/internal/model"
)

// MaxHARBytes bounds a HAR file. Browser recordings are large; one bigger than
// this is not a recording of an application someone clicked through.
const MaxHARBytes = 64 << 20

// MaxHAROperations bounds how many operations one HAR may contribute.
const MaxHAROperations = 2000

// HARResult is what a HAR contributed: operations, and an account of what was
// left out and why.
type HARResult struct {
	Operations []model.Operation
	Entries    int
	OffOrigin  int
	Assets     int
	Skipped    int
	Sensitive  int
	Truncated  bool
}

// harDoc decodes only what discovery uses: each request's method and URL.
// Headers, cookies, bodies, timings and responses are never read into
// memory, so nothing in them can be stored, logged or sent anywhere.
type harDoc struct {
	Log struct {
		Entries []struct {
			Request struct {
				Method string `json:"method"`
				URL    string `json:"url"`
			} `json:"request"`
		} `json:"entries"`
	} `json:"log"`
}

var assetExtensions = map[string]bool{
	".js": true, ".mjs": true, ".css": true, ".map": true, ".png": true, ".jpg": true, ".jpeg": true,
	".gif": true, ".svg": true, ".ico": true, ".webp": true, ".avif": true, ".woff": true, ".woff2": true,
	".ttf": true, ".otf": true, ".eot": true, ".mp4": true, ".webm": true, ".mp3": true,
}

var harMethods = map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true}

// tokenSegment matches a path segment that looks like a credential or a
// signed value rather than a route: a JWT, or a long run of URL-safe
// characters mixing letters and digits.
var tokenSegment = regexp.MustCompile(`^(?:eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*|[A-Za-z0-9_-]{32,})$`)

// ParseHAR reads a browser recording as discovery input.
//
// A HAR is evidence of which requests an application's own front end makes,
// which is how a single-page application's API is found without a browser. It
// is never permission to send any of them: nothing is replayed, and each
// operation it yields is planned and gated exactly like one from a
// specification. Only same-origin entries under the target's base path are
// kept, and each becomes a method, a path and the names of its query
// parameters — values are dropped, and an entry whose path carries a
// token-like segment is left out entirely.
func ParseHAR(data []byte, baseURL string) (HARResult, error) {
	var out HARResult
	if len(data) > MaxHARBytes {
		return out, fmt.Errorf("the HAR file exceeds %d bytes", MaxHARBytes)
	}
	var doc harDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return out, errors.New("the HAR file is not a JSON HAR document")
	}
	obs, err := newObserver(baseURL)
	if err != nil {
		return out, fmt.Errorf("the target's origin cannot be established: %v", err)
	}

	index := map[string]int{}
	for _, e := range doc.Log.Entries {
		out.Entries++
		ob, v := obs.observe(e.Request.Method, e.Request.URL)
		switch v {
		case observedOffOrigin:
			out.OffOrigin++
			continue
		case observedAsset:
			out.Assets++
			continue
		case observedSensitive:
			out.Sensitive++
			continue
		case observedSkipped:
			out.Skipped++
			continue
		}
		id := model.OperationID(ob.method, ob.path)
		if i, ok := index[id]; ok {
			addQueryParams(&out.Operations[i], ob.query)
			continue
		}
		if len(out.Operations) >= MaxHAROperations {
			out.Truncated = true
			continue
		}
		index[id] = len(out.Operations)
		out.Operations = append(out.Operations, obs.operation(ob,
			model.Source{Kind: model.SourceHAR, Ref: "har " + ob.method}))
	}
	model.SortOperations(out.Operations)
	return out, nil
}

func hasDotSegment(p string) bool {
	for _, s := range strings.Split(p, "/") {
		if s == "." || s == ".." {
			return true
		}
	}
	return false
}

func sensitivePath(p string) bool {
	for _, s := range strings.Split(p, "/") {
		if tokenSegment.MatchString(s) && strings.ContainsAny(s, "0123456789") {
			return true
		}
	}
	return false
}

// MergeOperations adds found operations to a surface. One whose method matches
// an existing operation and whose path fits that operation's template
// corroborates it — the source is recorded, nothing is duplicated — and the
// rest are added. It returns the merged surface and how many were added and
// corroborated.
func MergeOperations(existing, found []model.Operation) ([]model.Operation, int, int) {
	out := make([]model.Operation, len(existing))
	copy(out, existing)
	var added, corroborated int
	for _, f := range found {
		matched := false
		for i := range out {
			if out[i].Method != f.Method {
				continue
			}
			if model.PathMatchesTemplate(out[i].AbsolutePath(), f.AbsolutePath()) ||
				model.PathMatchesTemplate(out[i].PathTemplate, f.PathTemplate) {
				out[i].Sources = append(out[i].Sources, f.Sources...)
				// A parameter a front end was seen sending exists, whichever
				// source first described the route.
				addQueryParams(&out[i], queryParamNames(f))
				matched = true
				corroborated++
				break
			}
		}
		if !matched {
			out = append(out, f)
			added++
		}
	}
	model.SortOperations(out)
	return out, added, corroborated
}
