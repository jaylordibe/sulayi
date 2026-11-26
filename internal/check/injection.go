package check

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/jaylordibe/sulayi/internal/model"
	"github.com/jaylordibe/sulayi/internal/payload"
)

// Check identifiers for ADR-0023.
const (
	SQLInjectionID     = "sql-injection-boolean"
	ReflectedXSSID     = "reflected-xss"
	TemplateInjectID   = "template-injection"
	OpenRedirectID     = "open-redirect"
	CORSCredentialedID = "cors-credentialed-origin"
	StackTraceID       = "stack-trace-disclosure"
)

// applicable is the shared Applicable of the parameter checks.
func (in Injection) applicable(op model.Operation) (bool, model.BlockedCause, string) {
	_, cause, why := in.prepare(op)
	return cause == model.CauseNone, cause, why
}

// ---------------------------------------------------------------------------
// SQL injection, boolean-based.

// SQLInjection confirms an injectable query by its logic, not its errors: a
// true condition must leave the response unchanged and a false one change it,
// twice, with independent conditions.
type SQLInjection struct{ Injection }

func (SQLInjection) Metadata() Metadata {
	return Metadata{ID: SQLInjectionID, Title: "A parameter is interpolated into a SQL query",
		CWE: []string{"CWE-89"}, OWASP: []string{"A03:2021 Injection"}}
}

// RequiredProfile is standard: the payloads alter a vulnerable query's logic.
func (SQLInjection) RequiredProfile(model.Operation) model.Profile { return model.ProfileStandard }

func (c SQLInjection) Applicable(op model.Operation) (bool, model.BlockedCause, string) {
	return c.applicable(op)
}

type sqlContext struct {
	name                         string
	true1, false1, true2, false2 payload.Payload
}

var sqlContexts = []sqlContext{
	{"quoted string", payload.SQLStringTrue1, payload.SQLStringFalse1, payload.SQLStringTrue2, payload.SQLStringFalse2},
	{"number", payload.SQLNumberTrue1, payload.SQLNumberFalse1, payload.SQLNumberTrue2, payload.SQLNumberFalse2},
}

func (c SQLInjection) Run(ctx context.Context, op model.Operation) Result {
	t, cause, why := c.prepare(op)
	s := &sender{in: c.Injection}
	if cause != model.CauseNone {
		return s.result(model.DispositionUntested, cause, why, nil)
	}
	var suspected *model.Finding
	var unstable []string
	for _, p := range t.points {
		b1, blocked := s.baseline(ctx, t, p)
		if blocked != nil {
			return *blocked
		}
		b2, err := s.at(ctx, t, p, p.base)
		if err != nil {
			return s.fail(err, "the baseline request could not be completed")
		}
		if !is2xx(b1.Response) || !same(b1.Response, b2.Response, "") {
			unstable = append(unstable, p.String())
			continue
		}
		base := b1.Response
		for _, sc := range sqlContexts {
			holds := func(tp, fp payload.Payload) (bool, error) {
				tr, err := s.inject(ctx, t, p, p.base+tp.Value)
				if errors.Is(err, errUnaddressable) {
					return false, nil
				}
				if err != nil {
					return false, err
				}
				fr, err := s.inject(ctx, t, p, p.base+fp.Value)
				if errors.Is(err, errUnaddressable) {
					return false, nil
				}
				if err != nil {
					return false, err
				}
				return same(base, tr.Response, tp.Value) && !same(base, fr.Response, fp.Value), nil
			}
			first, err := holds(sc.true1, sc.false1)
			if err != nil {
				return s.fail(err, "an injected request could not be completed")
			}
			if !first {
				continue
			}
			second, err := holds(sc.true2, sc.false2)
			if err != nil {
				return s.fail(err, "an injected request could not be completed")
			}
			steps := []model.VerificationStep{
				{Name: "baseline-stable", Passed: true, Detail: "the baseline request returned the same response twice"},
				{Name: "first-condition-pair", Passed: true, Detail: fmt.Sprintf("%q left the response unchanged and %q changed it",
					sc.true1.Value, sc.false1.Value)},
				{Name: "second-condition-pair", Passed: second, Detail: fmt.Sprintf("%q and %q", sc.true2.Value, sc.false2.Value)},
			}
			repro := []string{
				fmt.Sprintf("GET with %s=%q — same response as %q", p.name, p.base+sc.true1.Value, p.base),
				fmt.Sprintf("GET with %s=%q — a different response", p.name, p.base+sc.false1.Value),
			}
			remediation := "Pass the parameter to the database as a bound parameter rather than building the " +
				"query from it. Validating its type is a useful second layer, not a substitute."
			expected := "the parameter is treated as data, so a condition appended to it changes nothing"
			if second {
				f := injectFinding(c.Metadata(), op, p, model.StateConfirmed, model.SeverityHigh, expected,
					fmt.Sprintf("in a %s context, two independent true conditions left the response unchanged and "+
						"their false counterparts changed it, so the value steers the query's logic", sc.name),
					"two independent condition pairs steered the response", steps, nil, remediation, repro)
				return s.result(model.DispositionExecuted, model.CauseNone,
					fmt.Sprintf("%s steers a SQL query (%s context)", p, sc.name), f)
			}
			if suspected == nil {
				suspected = injectFinding(c.Metadata(), op, p, model.StateSuspected, model.SeverityHigh, expected,
					fmt.Sprintf("in a %s context, one true/false condition pair changed the response as an "+
						"injectable query would, and the second did not agree", sc.name),
					"one condition pair only", steps, []string{"second-condition-pair: did not agree, so the " +
						"first may be coincidence"}, remediation, repro)
			}
		}
	}
	if suspected != nil {
		return s.result(model.DispositionExecuted, model.CauseNone, "one condition pair suggested SQL injection; "+
			"the second did not confirm it", suspected)
	}
	if len(unstable) == len(t.points) {
		return s.result(model.DispositionBlocked, model.CauseIndeterminateOutcome, "no parameter had a stable, "+
			"successful baseline, so a changed response could not be attributed to a payload: "+
			strings.Join(unstable, ", "), nil)
	}
	return s.clean("true and false SQL conditions were appended", t, unstableNote(unstable))
}

func unstableNote(unstable []string) string {
	if len(unstable) == 0 {
		return ""
	}
	return ". No stable, successful baseline for: " + strings.Join(unstable, ", ")
}

// ---------------------------------------------------------------------------
// Reflected XSS.

// ReflectedXSS confirms markup injection by a unique tag returned unencoded in
// HTML, right after the quote breakout that put it there, outside the
// elements where markup is not parsed as such.
type ReflectedXSS struct{ Injection }

func (ReflectedXSS) Metadata() Metadata {
	return Metadata{ID: ReflectedXSSID, Title: "A parameter is reflected into HTML without encoding",
		CWE: []string{"CWE-79"}, OWASP: []string{"A03:2021 Injection"}}
}

func (ReflectedXSS) RequiredProfile(model.Operation) model.Profile { return model.ProfileSafe }

func (c ReflectedXSS) Applicable(op model.Operation) (bool, model.BlockedCause, string) {
	return c.applicable(op)
}

func (c ReflectedXSS) Run(ctx context.Context, op model.Operation) Result {
	t, cause, why := c.prepare(op)
	s := &sender{in: c.Injection}
	if cause != model.CauseNone {
		return s.result(model.DispositionUntested, cause, why, nil)
	}
	var suspected *model.Finding
	for _, p := range t.points {
		base, blocked := s.baseline(ctx, t, p)
		if blocked != nil {
			return *blocked
		}
		if strings.Contains(string(base.Response.Body), payload.XSSTag) {
			continue
		}
		value := p.base + payload.XSSMarker.Value
		ex, err := s.inject(ctx, t, p, value)
		if errors.Is(err, errUnaddressable) {
			continue
		}
		if err != nil {
			return s.fail(err, "the injected request could not be completed")
		}
		resp := ex.Response
		ct := strings.ToLower(resp.HeaderValue("Content-Type"))
		body := string(resp.Body)
		i := strings.Index(body, payload.XSSTag)
		if i < 0 || !strings.Contains(ct, "text/html") {
			continue
		}
		where := rawTextContext(body[:i])
		// The tag is markup only if the breakout before it survived: a quote
		// encoded inside an attribute leaves the tag as attribute text.
		brokeOut := strings.HasSuffix(body[:i], `'>`)
		state := model.StateConfirmed
		result := "the tag was returned unencoded in HTML markup"
		var unavailable []string
		switch {
		case where != "":
			state = model.StateSuspected
			result = "the tag was returned unencoded, inside " + where
			unavailable = []string{"execution-context: inside " + where + " markup is not parsed as such, so " +
				"whether it executes depends on context the response alone does not show"}
		case !brokeOut:
			state = model.StateSuspected
			result = "the tag was returned unencoded, but the quote breakout before it was not"
			unavailable = []string{"execution-context: the characters before the tag were encoded, so it may " +
				"sit inside an attribute value rather than in markup"}
		}
		f := injectFinding(c.Metadata(), op, p, state, model.SeverityMedium,
			"the parameter is encoded for HTML before it is written into the page", result, result,
			[]model.VerificationStep{
				{Name: "absent-from-baseline", Passed: true, Detail: "the baseline response does not contain the tag"},
				{Name: "reflected-unencoded", Passed: true, Detail: "the response contains " + payload.XSSTag},
				{Name: "html-response", Passed: true, Detail: "Content-Type " + ct},
				{Name: "markup-context", Passed: state == model.StateConfirmed, Detail: result},
			}, unavailable,
			"Encode the value for the HTML context it is written into, through the template engine's escaping "+
				"rather than by hand.",
			[]string{fmt.Sprintf("GET with %s=%q — the response contains %s unencoded", p.name, value, payload.XSSTag)})
		if state == model.StateConfirmed {
			return s.result(model.DispositionExecuted, model.CauseNone, p.String()+" is reflected into HTML unencoded", f)
		}
		if suspected == nil {
			suspected = f
		}
	}
	if suspected != nil {
		return s.result(model.DispositionExecuted, model.CauseNone, "a marker was reflected unencoded where it "+
			"is not shown to be markup", suspected)
	}
	return s.clean("an HTML marker was injected", t, "")
}

// rawTextContext names the element or comment an offset falls in where markup
// is not parsed as such, or "" when it is in ordinary markup.
func rawTextContext(before string) string {
	lower := strings.ToLower(before)
	for _, el := range []string{"script", "style", "textarea", "title", "noscript", "xmp", "iframe",
		"noembed", "noframes", "template"} {
		if strings.LastIndex(lower, "<"+el) > strings.LastIndex(lower, "</"+el) {
			return "a <" + el + "> element"
		}
	}
	if strings.LastIndex(lower, "<!--") > strings.LastIndex(lower, "-->") {
		return "an HTML comment"
	}
	return ""
}

// ---------------------------------------------------------------------------
// Server-side template injection.

// TemplateInjection confirms evaluation by two products, of two expressions in
// the same syntax, that no response contains by chance.
type TemplateInjection struct{ Injection }

func (TemplateInjection) Metadata() Metadata {
	return Metadata{ID: TemplateInjectID, Title: "A parameter is evaluated by a server-side template engine",
		CWE: []string{"CWE-1336"}, OWASP: []string{"A03:2021 Injection"}}
}

// RequiredProfile is standard: a vulnerable engine computes the payload.
func (TemplateInjection) RequiredProfile(model.Operation) model.Profile { return model.ProfileStandard }

func (c TemplateInjection) Applicable(op model.Operation) (bool, model.BlockedCause, string) {
	return c.applicable(op)
}

func (c TemplateInjection) Run(ctx context.Context, op model.Operation) Result {
	t, cause, why := c.prepare(op)
	s := &sender{in: c.Injection}
	if cause != model.CauseNone {
		return s.result(model.DispositionUntested, cause, why, nil)
	}
	for _, p := range t.points {
		b1, blocked := s.baseline(ctx, t, p)
		if blocked != nil {
			return *blocked
		}
		b2, err := s.at(ctx, t, p, p.base)
		if err != nil {
			return s.fail(err, "the baseline request could not be completed")
		}
		inBaseline := func(product string) bool {
			return strings.Contains(string(b1.Response.Body), product) ||
				strings.Contains(string(b2.Response.Body), product)
		}
		if inBaseline(payload.SSTIProduct) || inBaseline(payload.SSTIProduct2) {
			continue
		}
		for i, tp := range payload.Templates {
			ex, err := s.inject(ctx, t, p, tp.Value)
			if errors.Is(err, errUnaddressable) {
				continue
			}
			if err != nil {
				return s.fail(err, "an injected request could not be completed")
			}
			if !strings.Contains(normalised(ex.Response, tp.Value), payload.SSTIProduct) {
				continue
			}
			second := payload.TemplatesSecond[i]
			ex2, err := s.inject(ctx, t, p, second.Value)
			if err != nil && !errors.Is(err, errUnaddressable) {
				return s.fail(err, "an injected request could not be completed")
			}
			if err != nil || !strings.Contains(normalised(ex2.Response, second.Value), payload.SSTIProduct2) {
				continue
			}
			f := injectFinding(c.Metadata(), op, p, model.StateConfirmed, model.SeverityHigh,
				"the parameter is passed to the template as data, never as template source",
				fmt.Sprintf("%q was rendered as %s and %q as %s", tp.Value, payload.SSTIProduct,
					second.Value, payload.SSTIProduct2),
				"the template engine evaluated both expressions",
				[]model.VerificationStep{
					{Name: "absent-from-baseline", Passed: true, Detail: "neither product is in either baseline"},
					{Name: "evaluated", Passed: true, Detail: fmt.Sprintf("%q became %s", tp.Value, payload.SSTIProduct)},
					{Name: "evaluated-again", Passed: true, Detail: fmt.Sprintf("%q became %s", second.Value, payload.SSTIProduct2)},
				}, nil,
				"Never build a template from request input; pass the value to the template as a variable.",
				[]string{fmt.Sprintf("GET with %s=%q — the response contains %s", p.name, tp.Value, payload.SSTIProduct)})
			return s.result(model.DispositionExecuted, model.CauseNone, p.String()+" is evaluated as a template", f)
		}
	}
	return s.clean("template expressions were injected", t, "")
}

// ---------------------------------------------------------------------------
// Open redirect.

// OpenRedirect confirms a redirect to a host the request chose.
type OpenRedirect struct{ Injection }

func (OpenRedirect) Metadata() Metadata {
	return Metadata{ID: OpenRedirectID, Title: "A parameter controls where the application redirects",
		CWE: []string{"CWE-601"}, OWASP: []string{"A01:2021 Broken Access Control"}}
}

func (OpenRedirect) RequiredProfile(model.Operation) model.Profile { return model.ProfileSafe }

func (c OpenRedirect) Applicable(op model.Operation) (bool, model.BlockedCause, string) {
	t, cause, why := c.prepare(op)
	if cause == model.CauseNone && !hasQueryPoint(t) {
		return false, model.CauseNoOracle, "a redirect target is carried in a query parameter, and this " +
			"operation declares none"
	}
	return cause == model.CauseNone, cause, why
}

func hasQueryPoint(t target) bool {
	for _, p := range t.points {
		if p.in == "query" {
			return true
		}
	}
	return false
}

func (c OpenRedirect) Run(ctx context.Context, op model.Operation) Result {
	t, cause, why := c.prepare(op)
	s := &sender{in: c.Injection}
	if cause != model.CauseNone {
		return s.result(model.DispositionUntested, cause, why, nil)
	}
	for _, p := range t.points {
		if p.in != "query" {
			continue
		}
		if _, blocked := s.baseline(ctx, t, p); blocked != nil {
			return *blocked
		}
		for _, rp := range payload.Redirects {
			ex, err := s.inject(ctx, t, p, rp.Value)
			if err != nil {
				return s.fail(err, "the injected request could not be completed")
			}
			resp := ex.Response
			if resp.Status < 300 || resp.Status > 399 {
				continue
			}
			loc, perr := url.Parse(resp.HeaderValue("Location"))
			if perr != nil || !strings.EqualFold(loc.Hostname(), payload.RedirectHost) {
				continue
			}
			f := injectFinding(c.Metadata(), op, p, model.StateConfirmed, model.SeverityMedium,
				"redirects go only to the application's own pages or an allow-list",
				fmt.Sprintf("the application answered %d with Location %s", resp.Status, resp.HeaderValue("Location")),
				"the redirect named the host the request chose",
				[]model.VerificationStep{{Name: "redirect-to-chosen-host", Passed: true,
					Detail: "Location names " + payload.RedirectHost + ", a reserved host that cannot resolve; it was not followed"}},
				nil, "Redirect only to relative paths on this application, or to an allow-list of hosts.",
				[]string{fmt.Sprintf("GET with %s=%q — %d to %s", p.name, rp.Value, resp.Status, resp.HeaderValue("Location"))})
			return s.result(model.DispositionExecuted, model.CauseNone, p.String()+" chooses the redirect target", f)
		}
	}
	return s.clean("off-site redirect targets were injected", t, "")
}

// ---------------------------------------------------------------------------
// Stack-trace disclosure.

// StackTrace confirms that an error handler discloses internals, by a stack
// trace a malformed value produces and the baseline does not.
type StackTrace struct{ Injection }

func (StackTrace) Metadata() Metadata {
	return Metadata{ID: StackTraceID, Title: "An error response discloses a stack trace",
		CWE: []string{"CWE-209"}, OWASP: []string{"A05:2021 Security Misconfiguration"}}
}

func (StackTrace) RequiredProfile(model.Operation) model.Profile { return model.ProfileSafe }

func (c StackTrace) Applicable(op model.Operation) (bool, model.BlockedCause, string) {
	return c.applicable(op)
}

// stackSignatures are frames as each runtime prints them, never a framework's
// name alone: a page mentioning a framework is not a stack trace. A trace
// inside a JSON string has its newlines as the two characters \n.
var stackSignatures = []struct {
	runtime string
	re      *regexp.Regexp
}{
	{"PHP", regexp.MustCompile(`#\d+ [^\n]*\.php\(\d+\)`)},
	{"PHP (debug JSON trace)", regexp.MustCompile(`"trace"\s*:\s*\[\s*\{\s*"file"\s*:\s*"[^"]+\.php"`)},
	{"Node.js", regexp.MustCompile(`(?:\n|\\n)\s+at [^\n]*?\(?[^\s()"]+\.(?:js|mjs|cjs|ts):\d+:\d+\)?`)},
	{"Python", regexp.MustCompile(`Traceback \(most recent call last\):\s*(?:\n|\\n)\s+File \\?"`)},
	{"Java", regexp.MustCompile(`(?:\n|\\n)\s*at [\w$.]+\([\w$]+\.java:\d+\)`)},
	{".NET", regexp.MustCompile(`(?:\n|\\n)\s*at [\w.<>]+\(.*?\) in [^\n]+?\.cs:line \d+`)},
}

// stackMatch returns the runtime whose frames a body carries, and the frames.
func stackMatch(body string) (string, string) {
	for _, s := range stackSignatures {
		if m := s.re.FindString(body); m != "" {
			return s.runtime, m
		}
	}
	return "", ""
}

func stackSignature(body string) string {
	rt, _ := stackMatch(body)
	return rt
}

func (c StackTrace) Run(ctx context.Context, op model.Operation) Result {
	t, cause, why := c.prepare(op)
	s := &sender{in: c.Injection}
	if cause != model.CauseNone {
		return s.result(model.DispositionUntested, cause, why, nil)
	}
	for _, p := range t.points {
		base, blocked := s.baseline(ctx, t, p)
		if blocked != nil {
			return *blocked
		}
		if stackSignature(string(base.Response.Body)) != "" {
			continue
		}
		value := p.base + payload.Malformed.Value
		ex, err := s.inject(ctx, t, p, value)
		if errors.Is(err, errUnaddressable) {
			continue
		}
		if err != nil {
			return s.fail(err, "the injected request could not be completed")
		}
		rt, frames := stackMatch(string(ex.Response.Body))
		if rt == "" {
			continue
		}
		// A debug page lists the server's configuration, often its secrets.
		// Only the frames that prove the finding are kept as evidence.
		last := &s.exchanges[len(s.exchanges)-1]
		resp := *last.Response
		resp.Body = []byte("[response body withheld; the stack frames it contained:]\n" + frames)
		last.Response = &resp
		f := injectFinding(c.Metadata(), op, p, model.StateConfirmed, model.SeverityLow,
			"an error is answered with a generic message; details go to the server's log",
			fmt.Sprintf("a malformed value produced a %s stack trace in a %d response", rt, ex.Response.Status),
			"the response contains stack frames",
			[]model.VerificationStep{
				{Name: "absent-from-baseline", Passed: true, Detail: "the baseline response carries no stack trace"},
				{Name: "stack-frames", Passed: true, Detail: rt + " frames in the response body"},
			}, nil,
			"Turn off debug output where this application is deployed, and render errors through a handler "+
				"that logs the detail and returns a generic message.",
			[]string{fmt.Sprintf("GET with %s=%q — the response contains a %s stack trace", p.name, value, rt)})
		return s.result(model.DispositionExecuted, model.CauseNone, "a malformed "+p.String()+" discloses a stack trace", f)
	}
	return s.clean("malformed values were sent", t, "")
}

// ---------------------------------------------------------------------------
// CORS.

// CORSCredentialed finds a signed-in route that lets any origin read it with
// credentials. It is confirmed only for a cookie session, the one credential a
// browser attaches to a cross-origin request by itself.
type CORSCredentialed struct{ Injection }

func (CORSCredentialed) Metadata() Metadata {
	return Metadata{ID: CORSCredentialedID, Title: "Any origin may read this signed-in response with credentials",
		CWE: []string{"CWE-942"}, OWASP: []string{"A05:2021 Security Misconfiguration"}}
}

func (CORSCredentialed) RequiredProfile(model.Operation) model.Profile { return model.ProfileSafe }

func (c CORSCredentialed) Applicable(op model.Operation) (bool, model.BlockedCause, string) {
	if op.Method != "GET" {
		return false, model.CauseNoOracle, "only GET operations are probed for cross-origin access"
	}
	if !op.DeclaresAuthRequired() {
		return false, model.CauseNoOracle, "nothing declares this operation as requiring sign-in, so a " +
			"cross-origin read of it exposes nothing a credential protects"
	}
	if c.Control == nil {
		return false, model.CauseMissingIdentity, "a credentialed cross-origin read needs a signed-in identity"
	}
	if len(op.RequiredPathParams()) > 0 {
		if _, ok := c.pathValues(op); !ok {
			return false, model.CauseMissingResource, "no fixture or created record fills this operation's " +
				"path parameters"
		}
	}
	return true, model.CauseNone, ""
}

func (c CORSCredentialed) Run(ctx context.Context, op model.Operation) Result {
	s := &sender{in: c.Injection}
	path, _ := c.pathValues(op)
	t := target{op: op, path: path}
	u, err := t.url(point{}, "")
	if err != nil {
		return s.result(model.DispositionBlocked, model.CauseMissingResource, err.Error(), nil)
	}
	ex, err := s.send(ctx, u, map[string][]string{"Origin": {payload.CORSOrigin.Value}})
	if err == nil && ex.Response == nil {
		err = errors.New("no response")
	}
	if err != nil {
		return s.fail(err, "the request could not be completed")
	}
	resp := ex.Response
	if resp.Status == 401 {
		c.Control.NoteSuspicious(ctx)
		return s.result(model.DispositionBlocked, model.CauseAuthenticationFailed, "the signed-in request was "+
			"refused with 401, so there was no signed-in response to expose", nil)
	}
	acao := resp.HeaderValue("Access-Control-Allow-Origin")
	acac := strings.EqualFold(strings.TrimSpace(resp.HeaderValue("Access-Control-Allow-Credentials")), "true")
	if !is2xx(resp) || acao != payload.CORSOrigin.Value || !acac {
		return s.result(model.DispositionExecuted, model.CauseNone, "a signed-in request from "+
			payload.CORSOrigin.Value+" was not granted credentialed cross-origin access", nil)
	}
	ambient := c.Control.Ambient()
	state, sev, conf := model.StateConfirmed, model.SeverityHigh, model.ConfidenceHigh
	result := "an arbitrary origin may read a signed-in response with the browser's cookies"
	var unavailable []string
	if !ambient {
		state, sev, conf = model.StateSuspected, model.SeverityLow, model.ConfidenceMedium
		result = "an arbitrary origin is granted credentialed access, but this identity signs in with a header " +
			"a browser does not attach cross-origin, so whether a cookie session is exposed is not shown"
		unavailable = []string{"ambient-credential: the identity authenticates with a header, not a cookie " +
			"session; configure a cookie-session identity to establish the impact"}
	}
	f := &model.Finding{
		CheckID: CORSCredentialedID, Title: c.Metadata().Title, State: state,
		Severity: sev, Confidence: conf, CWE: c.Metadata().CWE,
		OWASP: c.Metadata().OWASP, OperationID: op.ID, IdentityID: c.Control.ID(),
		Expected: "credentialed cross-origin reads are granted only to an allow-list of trusted origins",
		Actual: fmt.Sprintf("the response to %s, a host nobody controls, carried Access-Control-Allow-Origin: %s "+
			"and Access-Control-Allow-Credentials: true", payload.CORSOrigin.Value, acao),
		Verification: model.VerificationRecord{Strategy: CORSCredentialedID, Performed: true,
			Result: result, Unavailable: unavailable,
			Steps: []model.VerificationStep{
				{Name: "signed-in-response", Passed: true, Detail: fmt.Sprintf("status %d as %s", resp.Status, c.Control.ID())},
				{Name: "origin-echoed", Passed: true, Detail: "Access-Control-Allow-Origin: " + acao},
				{Name: "credentials-allowed", Passed: true, Detail: "Access-Control-Allow-Credentials: true"},
				{Name: "ambient-credential", Passed: ambient, Detail: result},
			}},
		Remediation: "Allow credentialed cross-origin requests only from an explicit list of origins; never echo " +
			"the request's Origin.",
		Reproduction: []string{fmt.Sprintf("GET %s as %s with Origin: %s — the origin is echoed with credentials allowed",
			u, c.Control.ID(), payload.CORSOrigin.Value)},
	}
	return s.result(model.DispositionExecuted, model.CauseNone, result, f)
}
