package check

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/jaylordibe/sulayi/internal/httpx"
	"github.com/jaylordibe/sulayi/internal/identity"
	"github.com/jaylordibe/sulayi/internal/model"
	"github.com/jaylordibe/sulayi/internal/resource"
)

// MaxInjectedParams bounds how many parameters of one operation are injected
// into. Each costs several requests; the rest are named in the ledger detail.
const MaxInjectedParams = 8

// baselineQueryValue fills every query parameter that is not being injected,
// and is the value an injected one starts from (ADR-0023).
const baselineQueryValue = "1"

// Injection is what every injection check shares: how an operation is
// addressed, which of its parameters receive payloads, and who sends them.
type Injection struct {
	Client *httpx.Client
	// Control sends the requests when it is usable, so routes behind sign-in
	// are reachable; otherwise they are sent anonymously.
	Control *identity.Control
	// Resources fill path parameters, as for every other check.
	Resources []resource.Fixture
	// Now supplies the clock, injected so runs are reproducible.
	Now func() time.Time
}

func (in Injection) now() time.Time {
	if in.Now != nil {
		return in.Now()
	}
	return time.Now()
}

// point is one parameter that receives payloads.
type point struct {
	name string
	in   string // "query" or "path"
	// base is the value the parameter normally carries.
	base string
}

func (p point) String() string { return p.in + " parameter " + p.name }

// target is an operation ready for injection.
type target struct {
	op     model.Operation
	path   map[string]string
	query  []string // query parameter names, sorted
	points []point
	// skipped names parameters beyond MaxInjectedParams.
	skipped []string
}

// prepare addresses an operation and lists its injection points. It returns a
// reason when the operation cannot be injected into.
func (in Injection) prepare(op model.Operation) (target, model.BlockedCause, string) {
	t := target{op: op, path: map[string]string{}}
	if op.Method != http.MethodGet {
		return t, model.CauseNoOracle, "payloads are sent only in GET operations; request bodies and " +
			"state-changing operations are not assessed for injection (ADR-0023)"
	}
	if req := op.RequiredPathParams(); len(req) > 0 {
		values, ok := in.pathValues(op)
		if !ok {
			return t, model.CauseMissingResource, fmt.Sprintf("path parameter(s) %s cannot be filled from "+
				"any fixture or created record, so the operation cannot be addressed", strings.Join(req, ", "))
		}
		t.path = values
	}
	var pts []point
	for _, p := range op.Parameters {
		switch p.In {
		case "query":
			t.query = append(t.query, p.Name)
			pts = append(pts, point{name: p.Name, in: "query", base: baselineQueryValue})
		case "path":
			if v, ok := t.path[p.Name]; ok {
				pts = append(pts, point{name: p.Name, in: "path", base: v})
			}
		}
	}
	sort.Strings(t.query)
	sort.Slice(pts, func(i, j int) bool {
		if pts[i].in != pts[j].in {
			return pts[i].in > pts[j].in // query before path
		}
		return pts[i].name < pts[j].name
	})
	if len(pts) == 0 {
		return t, model.CauseNoOracle, "the operation declares no query or path parameter to inject into"
	}
	if len(pts) > MaxInjectedParams {
		for _, p := range pts[MaxInjectedParams:] {
			t.skipped = append(t.skipped, p.String())
		}
		pts = pts[:MaxInjectedParams]
	}
	t.points = pts
	return t, model.CauseNone, ""
}

// pathValues fills path parameters from the first fixture that applies.
func (in Injection) pathValues(op model.Operation) (map[string]string, bool) {
	fixtures := make([]resource.Fixture, len(in.Resources))
	copy(fixtures, in.Resources)
	resource.SortFixtures(fixtures)
	for _, f := range fixtures {
		if !f.AppliesTo(op) {
			continue
		}
		if _, err := resource.Bind(op, f.Values); err == nil {
			return f.Values, true
		}
	}
	return nil, false
}

// url builds the request with one point carrying value and every other
// parameter its baseline.
func (t target) url(p point, value string) (string, error) {
	path := make(map[string]string, len(t.path))
	for k, v := range t.path {
		path[k] = v
	}
	if p.in == "path" {
		path[p.name] = value
	}
	b, err := resource.Bind(t.op, path)
	if err != nil {
		return "", err
	}
	if len(t.query) == 0 {
		return b.URL, nil
	}
	q := make([]string, 0, len(t.query))
	for _, name := range t.query {
		v := baselineQueryValue
		if p.in == "query" && p.name == name {
			v = value
		}
		q = append(q, url.QueryEscape(name)+"="+url.QueryEscape(v))
	}
	return b.URL + "?" + strings.Join(q, "&"), nil
}

// sender sends a check's requests and records who sent them.
type sender struct {
	in        Injection
	exchanges []model.Exchange
	uses      []ControlUse
	// injected names the points that received at least one payload, so a
	// check that could send none says so instead of reporting a clean run.
	injected map[string]bool
}

// errBlocked carries why a request was not sent as the configured identity.
type errBlocked struct {
	cause  model.BlockedCause
	detail string
}

func (e *errBlocked) Error() string { return e.detail }

func (s *sender) send(ctx context.Context, u string, extra map[string][]string) (model.Exchange, error) {
	header := map[string][]string{
		"Accept":        {"text/html,application/json;q=0.9,*/*;q=0.8"},
		"Cache-Control": {"no-cache"},
		"Pragma":        {"no-cache"},
	}
	for k, v := range extra {
		header[k] = v
	}
	// With an identity configured, its requests are never quietly sent
	// anonymously instead: a route behind sign-in would answer 401 to every
	// payload and read as clean.
	if c := s.in.Control; c != nil {
		if ok, cause, why := c.Usable(); !ok {
			return model.Exchange{}, &errBlocked{cause: cause, detail: why}
		}
		ex, err := c.Do(ctx, http.MethodGet, u, header)
		s.uses = append(s.uses, ControlUse{IdentityID: c.ID(), At: s.in.now()})
		s.record(ex)
		return ex, err
	}
	ex, err := s.in.Client.Do(ctx, httpx.Request{Method: http.MethodGet, URL: u, Header: header})
	s.record(ex)
	return ex, err
}

func (s *sender) record(ex model.Exchange) {
	if ex.Request.URL != "" {
		s.exchanges = append(s.exchanges, ex)
	}
}

// errUnaddressable means a value cannot fill its parameter, such as a payload
// with a separator in a path segment. Nothing was sent.
var errUnaddressable = errors.New("the value cannot fill this parameter")

// at sends the request with one point carrying value.
func (s *sender) at(ctx context.Context, t target, p point, value string) (model.Exchange, error) {
	u, err := t.url(p, value)
	if err != nil {
		return model.Exchange{}, fmt.Errorf("%w: %v", errUnaddressable, err)
	}
	ex, err := s.send(ctx, u, nil)
	if err == nil && ex.Response == nil {
		err = fmt.Errorf("no response")
	}
	return ex, err
}

// inject sends a payload at a point and records that the point received one.
func (s *sender) inject(ctx context.Context, t target, p point, value string) (model.Exchange, error) {
	ex, err := s.at(ctx, t, p, value)
	if err == nil {
		if s.injected == nil {
			s.injected = map[string]bool{}
		}
		s.injected[p.String()] = true
	}
	return ex, err
}

// baseline sends a point's baseline and decides whether the operation can be
// tested through it. A 401 or 403 means the caller cannot reach the route, so
// a payload's answer would say nothing; a 401 to the identity also prompts a
// liveness probe, as for every other check.
func (s *sender) baseline(ctx context.Context, t target, p point) (model.Exchange, *Result) {
	ex, err := s.at(ctx, t, p, p.base)
	if err != nil {
		r := s.fail(err, "the baseline request could not be completed")
		return ex, &r
	}
	switch ex.Response.Status {
	case http.StatusUnauthorized:
		if c := s.in.Control; c != nil {
			c.NoteSuspicious(ctx)
			r := s.result(model.DispositionBlocked, model.CauseAuthenticationFailed, "the baseline was "+
				"refused with 401 as "+c.ID()+", so a payload's answer would say nothing", nil)
			return ex, &r
		}
		r := s.result(model.DispositionBlocked, model.CauseMissingIdentity, "the route requires sign-in and "+
			"no identity is configured, so a payload's answer would be a 401 that says nothing", nil)
		return ex, &r
	case http.StatusForbidden:
		r := s.result(model.DispositionBlocked, model.CauseInsufficientPrivilege, "the baseline was refused "+
			"with 403, so the caller cannot reach this route and a payload's answer would say nothing", nil)
		return ex, &r
	}
	return ex, nil
}

// fail turns a send error into a blocked result with its cause.
func (s *sender) fail(err error, what string) Result {
	var b *errBlocked
	if errors.As(err, &b) {
		return s.result(model.DispositionBlocked, b.cause, b.detail, nil)
	}
	return s.result(model.DispositionBlocked, transportCause(err), what+": "+summarize(err), nil)
}

// clean is the result when nothing was found: executed if at least one point
// received a payload, untested if none could.
func (s *sender) clean(what string, t target, note string) Result {
	if len(s.injected) == 0 {
		return s.result(model.DispositionUntested, model.CauseNoOracle, "no parameter could carry the "+
			"payload — a path segment cannot hold some of its characters — so nothing was injected"+note, nil)
	}
	return s.result(model.DispositionExecuted, model.CauseNone, executedDetail(what, t, s.injected)+note, nil)
}

func (s *sender) result(d model.Disposition, cause model.BlockedCause, detail string, f *model.Finding) Result {
	return Result{Disposition: d, Cause: cause, Detail: detail, Finding: f,
		Exchanges: s.exchanges, ControlsUsed: s.uses}
}

// injectFinding builds an injection finding.
func injectFinding(meta Metadata, op model.Operation, p point, state model.FindingState, sev model.Severity,
	expected, actual, result string, steps []model.VerificationStep, unavailable []string,
	remediation string, repro []string) *model.Finding {
	conf := model.ConfidenceMedium
	if state == model.StateConfirmed {
		conf = model.ConfidenceHigh
	}
	return &model.Finding{
		CheckID: meta.ID, Title: meta.Title, State: state, Severity: sev, Confidence: conf,
		CWE: meta.CWE, OWASP: meta.OWASP, OperationID: op.ID,
		Expected: expected, Actual: fmt.Sprintf("%s: %s", p, actual),
		Verification: model.VerificationRecord{Strategy: meta.ID, Steps: steps, Performed: true,
			Result: result, Unavailable: unavailable},
		Remediation: remediation, Reproduction: repro,
	}
}

// executedDetail says what was injected and what was not.
func executedDetail(what string, t target, injected map[string]bool) string {
	var names, not []string
	for _, p := range t.points {
		if injected[p.String()] {
			names = append(names, p.String())
		} else {
			not = append(not, p.String())
		}
	}
	d := fmt.Sprintf("%s in %s; none showed it", what, strings.Join(names, ", "))
	if len(not) > 0 {
		d += ". Could not carry the payload: " + strings.Join(not, ", ")
	}
	if len(t.skipped) > 0 {
		d += fmt.Sprintf(". Not injected, beyond the %d-parameter bound: %s", MaxInjectedParams,
			strings.Join(t.skipped, ", "))
	}
	return d
}

// normalised removes every encoding of the injected text from a response body,
// so an application that echoes its input does not differ for that reason.
func normalised(resp *model.CapturedResponse, injected string) string {
	if resp == nil {
		return ""
	}
	body := string(resp.Body)
	if injected == "" {
		return body
	}
	js, _ := json.Marshal(injected)
	variants := []string{
		injected,
		html.EscapeString(injected),
		strings.ReplaceAll(html.EscapeString(injected), "&#39;", "&#039;"),
		strings.ReplaceAll(html.EscapeString(injected), "&#39;", "&#x27;"),
		strings.Trim(string(js), `"`),
		strings.ReplaceAll(strings.Trim(string(js), `"`), "'", `'`),
		strings.ReplaceAll(html.EscapeString(injected), "&#39;", "&apos;"),
		url.QueryEscape(injected),
	}
	sort.Slice(variants, func(i, j int) bool { return len(variants[i]) > len(variants[j]) })
	for _, v := range variants {
		if v != "" {
			body = strings.ReplaceAll(body, v, "")
		}
	}
	return body
}

// same reports whether two responses carry the same thing once the injected
// text is removed from the second.
func same(a, b *model.CapturedResponse, injected string) bool {
	if a == nil || b == nil || a.Status != b.Status {
		return false
	}
	return normalised(a, "") == normalised(b, injected)
}

func is2xx(r *model.CapturedResponse) bool { return r != nil && r.Status >= 200 && r.Status <= 299 }
