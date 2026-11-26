// Package record creates the records an assessment owns and removes them
// afterwards (ADR-0022).
//
// A record created as an identity is the one thing ownership can be stated of
// without inferring it: the run watched that identity create it. Each record is
// declared by the operator as a recipe, created through the application's own
// API before the assessment is planned, used as a cross-owner fixture, and
// deleted as its creator at the end, with the deletion verified by reading it
// again. A record that could not be removed is reported by address, because
// somebody's data is still there.
package record

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jaylordibe/sulayi/internal/access"
	"github.com/jaylordibe/sulayi/internal/httpx"
	"github.com/jaylordibe/sulayi/internal/identity"
	"github.com/jaylordibe/sulayi/internal/jsonpointer"
	"github.com/jaylordibe/sulayi/internal/model"
	"github.com/jaylordibe/sulayi/internal/outcome"
	"github.com/jaylordibe/sulayi/internal/resource"
)

// CleanupTimeout bounds the removal of one record, after an interrupt too.
const CleanupTimeout = 30 * time.Second

// RequestsPerRecord is what removing one record costs: the read that shows it
// is addressable, the DELETE, and the read that verifies it.
const RequestsPerRecord = 3

// Value is one creation body field: a literal, the creating identity's own id,
// or a value random per run. Exactly one is set.
type Value struct {
	Literal any
	Self    bool
	Random  bool
}

// Recipe declares how to create one kind of record and how to remove it.
type Recipe struct {
	// Type names the kind of record; it prefixes the fixture ids.
	Type string
	// CreatePath is the collection the record is POSTed to, on the target's
	// origin.
	CreatePath string
	// Body is the JSON object sent. It can reference no credential.
	Body map[string]Value
	// IDPointer locates the new record's id in the creation response.
	IDPointer string
	// DeletePath addresses one record, with exactly one {param} segment.
	DeletePath string
	// As lists the identities that create one each. Empty means every one.
	As []string
}

var typePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,39}$`)

// Validate checks a recipe, returning operator-facing problems.
func (r Recipe) Validate(path string, knownIdentities map[string]bool) []string {
	var problems []string
	if !typePattern.MatchString(r.Type) {
		problems = append(problems, fmt.Sprintf("%s.type %q must be 1-40 lowercase letters, digits, hyphen "+
			"or underscore", path, r.Type))
	}
	if !strings.HasPrefix(r.CreatePath, "/") || strings.ContainsAny(r.CreatePath, "?#{}") {
		problems = append(problems, fmt.Sprintf("%s.create.path %q must be a path beginning with / with no "+
			"query, fragment or parameter", path, r.CreatePath))
	}
	if len(r.Body) == 0 {
		problems = append(problems, path+".create.body must name at least one field")
	}
	for _, k := range sortedKeys(r.Body) {
		v := r.Body[k]
		n := 0
		if v.Literal != nil {
			n++
		}
		if v.Self {
			n++
		}
		if v.Random {
			n++
		}
		if n != 1 {
			problems = append(problems, fmt.Sprintf("%s.create.body.%s must set exactly one of value, self "+
				"or random", path, k))
		}
	}
	if !strings.HasPrefix(r.IDPointer, "/") {
		problems = append(problems, fmt.Sprintf("%s.id %q must be a JSON pointer beginning with /", path, r.IDPointer))
	}
	if _, err := deleteParam(r.DeletePath); err != nil {
		problems = append(problems, fmt.Sprintf("%s.delete: %v", path, err))
	}
	for _, id := range r.As {
		if !knownIdentities[id] {
			problems = append(problems, fmt.Sprintf("%s.as names %q, which is not a configured identity", path, id))
		}
	}
	return problems
}

// deleteParam returns the one {param} in a delete path.
func deleteParam(p string) (string, error) {
	if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "?#") {
		return "", fmt.Errorf("%q must be a path beginning with / with no query or fragment", p)
	}
	var names []string
	for _, seg := range strings.Split(strings.Trim(p, "/"), "/") {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") && len(seg) > 2 {
			names = append(names, seg[1:len(seg)-1])
		} else if strings.ContainsAny(seg, "{}") {
			return "", fmt.Errorf("%q has a parameter that is not a whole segment", p)
		}
	}
	if len(names) != 1 {
		return "", fmt.Errorf("%q must contain exactly one {param} segment, the record's id", p)
	}
	return names[0], nil
}

// Created is one record this run attempted to create, and what became of it.
type Created struct {
	Recipe Recipe
	// Owner is the identity that created it.
	Owner string
	// ID is the record's id as the application returned it.
	ID string
	// URL addresses the record; empty when it was never addressable.
	URL string
	// Exists is true when the application may hold the record: the creation
	// request was answered with success, or could not be shown not to have
	// been.
	Exists bool
	// Problem says why it was not created, or not usable as a fixture.
	Problem string
	// Removed is true only when the deletion succeeded and a read as the
	// creator confirmed the record is gone.
	Removed bool
	// RemovalProblem says why it was not shown to be removed.
	RemovalProblem string
}

// Usable reports whether the record exists and is addressable as a fixture.
func (c Created) Usable() bool { return c.Exists && c.URL != "" && c.Problem == "" }

// Guard is the part of the safety guard creation needs.
type Guard interface {
	GrantCreate(rawURL string, body []byte) error
	GrantCleanup(rawURL string) error
}

// Options configures creation.
type Options struct {
	// Origin is the target's scheme and host; recipe paths are resolved on it.
	Origin     string
	Recipes    []Recipe
	Identities *identity.Set
	Guard      Guard
	Profile    model.Profile
}

// Create creates one record per recipe per identity, registering each
// creation and the deletion of what it created with the guard. It must run
// before the guard is sealed. Records are created in configuration order, so
// fixture ids are stable across runs.
func Create(ctx context.Context, opts Options) []Created {
	var out []Created
	for _, r := range opts.Recipes {
		for _, ctl := range creators(opts.Identities, r) {
			out = append(out, create(ctx, opts, r, ctl))
		}
	}
	return out
}

func creators(set *identity.Set, r Recipe) []*identity.Control {
	if set == nil {
		return nil
	}
	if len(r.As) == 0 {
		return set.Controls()
	}
	var out []*identity.Control
	for _, id := range r.As {
		if c, ok := set.ByID(id); ok {
			out = append(out, c)
		}
	}
	return out
}

func create(ctx context.Context, opts Options, r Recipe, ctl *identity.Control) Created {
	c := Created{Recipe: r, Owner: ctl.ID()}
	if opts.Profile == model.ProfileSafe {
		c.Problem = "not created: the safe profile sends nothing that changes state"
		return c
	}
	if ok, _, why := ctl.Usable(); !ok {
		c.Problem = "not created: " + why
		return c
	}
	if r.needsSelf() {
		if _, ok := ctl.SelfID(); !ok {
			// The own id is read from the liveness canary, which may not have
			// run yet for an identity that did not sign in through a login.
			ctl.Probe(ctx)
		}
	}
	body, err := buildBody(r, ctl)
	if err != nil {
		c.Problem = "not created: " + err.Error()
		return c
	}
	createURL := strings.TrimRight(opts.Origin, "/") + r.CreatePath
	if opts.Guard != nil {
		if err := opts.Guard.GrantCreate(createURL, body); err != nil {
			c.Problem = "not created: the creation could not be registered with the safety guard: " + err.Error()
			return c
		}
	}
	ex, err := ctl.DoWithBody(ctx, http.MethodPost, createURL, map[string][]string{
		"Content-Type": {"application/json"},
		"Accept":       {"application/json"},
	}, body)
	if err != nil || ex.Response == nil {
		c.Exists = !httpx.NotSent(err)
		c.Problem = fmt.Sprintf("the creation request failed: %v", err)
		if c.Exists {
			c.RemovalProblem = "the creation request may have reached the target, but no id came back, so " +
				"the record cannot be addressed to remove it"
		}
		return c
	}
	if s := ex.Response.Status; s < 200 || s > 299 {
		c.Problem = fmt.Sprintf("not created: the application answered the creation with %d", s)
		return c
	}
	c.Exists = true
	id, ok := jsonpointer.String(ex.Response.Body, r.IDPointer)
	if !ok || id == "" {
		c.Problem = fmt.Sprintf("created, but no id was found at %s in the response", r.IDPointer)
		c.RemovalProblem = "the record's id is unknown, so it cannot be addressed to remove it"
		return c
	}
	c.ID = id
	u, err := itemURL(opts.Origin, r.DeletePath, id)
	if err != nil {
		c.Problem = "created, but its id cannot address it: " + err.Error()
		c.RemovalProblem = "the id the application returned is not usable in a URL, so it was not addressed"
		return c
	}
	c.URL = u
	if opts.Guard != nil {
		if err := opts.Guard.GrantCleanup(u); err != nil {
			c.Problem = "created, but its removal could not be registered with the safety guard: " + err.Error()
			c.RemovalProblem = "its removal was not permitted"
			return c
		}
	}
	return c
}

func (r Recipe) needsSelf() bool {
	for _, v := range r.Body {
		if v.Self {
			return true
		}
	}
	return false
}

// buildBody renders the creation body. Map keys are encoded in sorted order,
// so the exact body the guard registered is the one sent.
func buildBody(r Recipe, ctl *identity.Control) ([]byte, error) {
	obj := make(map[string]any, len(r.Body))
	for k, v := range r.Body {
		switch {
		case v.Self:
			self, ok := ctl.SelfID()
			if !ok {
				return nil, fmt.Errorf("field %q needs identity %s's own id, and none was read; set "+
					"identities[].liveness.self", k, ctl.ID())
			}
			obj[k] = self
		case v.Random:
			b := make([]byte, 8)
			if _, err := rand.Read(b); err != nil {
				return nil, err
			}
			obj[k] = "sulayi-" + hex.EncodeToString(b)
		default:
			obj[k] = v.Literal
		}
	}
	return json.Marshal(obj)
}

// itemURL binds the id into the delete path through the same validation and
// origin check as every fixture value.
func itemURL(origin, deletePath, id string) (string, error) {
	param, err := deleteParam(deletePath)
	if err != nil {
		return "", err
	}
	op := model.Operation{
		Method: http.MethodDelete, PathTemplate: deletePath, BaseURL: origin,
		Parameters: []model.Parameter{{Name: param, In: "path", Required: true}},
	}
	b, err := resource.Bind(op, map[string]string{param: id})
	if err != nil {
		return "", err
	}
	return b.URL, nil
}

// Remove deletes every record that exists, as its creator, and verifies each
// is gone. It ignores cancellation: it runs after an interrupt precisely
// because the records are still there.
func Remove(ctx context.Context, created []Created, set *identity.Set, signals outcome.Signals) []Created {
	out := make([]Created, len(created))
	copy(out, created)
	for i := range out {
		c := &out[i]
		if !c.Exists || c.URL == "" {
			continue
		}
		ctl, ok := set.ByID(c.Owner)
		if !ok {
			c.RemovalProblem = "its creator is no longer available"
			continue
		}
		rc, cancel := context.WithTimeout(httpx.Cleanup(context.WithoutCancel(ctx)), CleanupTimeout)
		c.Removed, c.RemovalProblem = remove(rc, ctl, c.URL, signals)
		cancel()
	}
	return out
}

func remove(ctx context.Context, ctl *identity.Control, u string, signals outcome.Signals) (bool, string) {
	headers := map[string][]string{"Accept": {"application/json"}}
	readHeaders := map[string][]string{"Accept": {"application/json"}, "Cache-Control": {"no-cache"}}
	// The creator reads the record first. Only then does a not-found after the
	// deletion mean it is gone, rather than that no read addresses it at all.
	pre, err := ctl.Do(ctx, http.MethodGet, u, readHeaders)
	readable := err == nil && pre.Response != nil && pre.Response.Status >= 200 && pre.Response.Status <= 299
	del, err := ctl.Do(ctx, http.MethodDelete, u, headers)
	if err != nil || del.Response == nil {
		return false, fmt.Sprintf("the deletion failed: %v", err)
	}
	if s := del.Response.Status; s < 200 || s > 299 {
		return false, fmt.Sprintf("the application answered the deletion with %d", s)
	}
	if !readable {
		return false, "the deletion was accepted, but the record could not be read before it, so a " +
			"not-found afterwards would not show it is gone; its removal is not verified"
	}
	get, err := ctl.Do(ctx, http.MethodGet, u, readHeaders)
	if err != nil || get.Response == nil {
		return false, fmt.Sprintf("the deletion was accepted, but the read that verifies it failed: %v", err)
	}
	// Gone means not found: a 404 or 410, or a response the operator's
	// outcome signals name as not found. A 403 is not accepted, because a
	// record its creator may no longer read has not been shown to be gone.
	if s := get.Response.Status; s == http.StatusNotFound || s == http.StatusGone {
		return true, ""
	}
	if cls := outcome.Classify(get.Response, signals); cls.Outcome == model.OutcomeNotFound {
		return true, ""
	}
	return false, fmt.Sprintf("the deletion was accepted, but reading the record afterwards was answered "+
		"with %d rather than not found, so its removal is not verified", get.Response.Status)
}

// Fixtures turns the usable records into cross-owner fixtures.
//
// A record addresses an operation at the record's own path. Only reads are used, and only where an access.owned rule declares
// the path's records private to their creator: an undeclared path has no
// expectation. One fixture is made per record and rule, so each carries the
// non-owners that rule expects to be refused.
func Fixtures(created []Created, ops []model.Operation, rules *access.Rules, set *identity.Set) []resource.Fixture {
	var out []resource.Fixture
	seq := map[string]int{}
	for _, c := range created {
		if !c.Usable() {
			continue
		}
		seq[c.Recipe.Type]++
		type group struct {
			rule   access.OwnedRule
			ops    []string
			values map[string]string
		}
		var groups []*group
		for _, op := range ops {
			if !model.IsSafeMethod(op.Method) || op.Method == http.MethodOptions {
				continue
			}
			name, ok := addresses(c.Recipe.DeletePath, op)
			if !ok {
				continue
			}
			rule, declared := rules.Owned(op.AbsolutePath())
			if !declared {
				continue
			}
			var g *group
			for _, existing := range groups {
				if existing.rule.Index == rule.Index {
					g = existing
				}
			}
			if g == nil {
				g = &group{rule: rule, values: map[string]string{}}
				groups = append(groups, g)
			}
			g.ops = append(g.ops, op.ID)
			g.values[name] = c.ID
		}
		for i, g := range groups {
			id := fmt.Sprintf("%s-%d", c.Recipe.Type, seq[c.Recipe.Type])
			if len(groups) > 1 {
				id = fmt.Sprintf("%s-%d", id, i+1)
			}
			var nonOwners []string
			for _, ctl := range set.Controls() {
				if ctl.ID() != c.Owner && !g.rule.Reaches(ctl.Role()) {
					nonOwners = append(nonOwners, ctl.ID())
				}
			}
			if len(nonOwners) == 0 {
				continue
			}
			sort.Strings(g.ops)
			out = append(out, resource.Fixture{
				ID: id, Type: c.Recipe.Type, Owner: c.Owner,
				CrossOwnerAccess: resource.CrossOwnerDenied,
				Values:           g.values, Operations: g.ops, NonOwners: nonOwners,
				Provenance: resource.ProvenanceAPICreated,
			})
		}
	}
	return out
}

// Addresses reports whether an operation addresses a record of this recipe
// at its own path.
func (r Recipe) Addresses(op model.Operation) bool {
	_, ok := addresses(r.DeletePath, op)
	return ok
}

// addresses reports whether an operation addresses the record itself, at the
// record's own path, returning the operation's parameter name in the id
// position. A sub-collection under it (/workspaces/{id}/memberships) is not
// the record: an application that narrows it to the caller's own rows answers
// another identity with an empty success, which is correct, not a leak.
func addresses(deletePath string, op model.Operation) (string, bool) {
	rec := strings.Split(strings.Trim(deletePath, "/"), "/")
	got := strings.Split(strings.Trim(op.AbsolutePath(), "/"), "/")
	if len(got) != len(rec) {
		return "", false
	}
	var name string
	for i, seg := range got {
		param := len(seg) > 2 && seg[0] == '{' && seg[len(seg)-1] == '}'
		recParam := strings.HasPrefix(rec[i], "{")
		switch {
		case recParam && param:
			name = seg[1 : len(seg)-1]
		case recParam || param || seg != rec[i]:
			return "", false
		}
	}
	return name, name != ""
}

func sortedKeys(m map[string]Value) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
