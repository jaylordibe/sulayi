package httpx

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// ErrNotSent wraps a failure that happened before a request left this process:
// a pacing wait that was cancelled, for example. It lets a caller distinguish
// "the target never saw this" from "this may have reached the target", which is
// the distinction that decides whether a write needs cleaning up.
type ErrNotSent struct{ Err error }

func (e *ErrNotSent) Error() string { return "httpx: not sent: " + e.Err.Error() }
func (e *ErrNotSent) Unwrap() error { return e.Err }

// ErrBudgetExceeded reports that the assessment's request budget is spent.
type ErrBudgetExceeded struct {
	Limit   int
	Cleanup bool
}

func (e *ErrBudgetExceeded) Error() string {
	if e.Cleanup {
		return fmt.Sprintf("httpx: the cleanup allowance above the %d-request budget is spent", e.Limit)
	}
	return fmt.Sprintf("httpx: the assessment's %d-request budget is spent", e.Limit)
}

// NotSent reports whether err means the request never left this process: it
// was refused by the safety guard, by scope or by the budget, or it was
// cancelled while waiting to be sent.
func NotSent(err error) bool {
	var (
		refused  *ErrRefused
		scope    *ErrOutOfScope
		budget   *ErrBudgetExceeded
		notSent  *ErrNotSent
		anything = err != nil
	)
	return anything && (errors.As(err, &refused) || errors.As(err, &scope) ||
		errors.As(err, &budget) || errors.As(err, &notSent))
}

type cleanupKey struct{}

// Cleanup marks ctx as carrying requests that restore state the assessment
// changed. Those requests draw on a small allowance above the request budget,
// so a run that spent its budget can still put a fixture back.
//
// The mark is a claim made by the caller, which is why the allowance is small
// and fixed: marking ordinary work as cleanup buys at most that many requests.
// It changes nothing about scope or the safety guard.
func Cleanup(ctx context.Context) context.Context {
	return context.WithValue(ctx, cleanupKey{}, true)
}

func isCleanup(ctx context.Context) bool {
	v, _ := ctx.Value(cleanupKey{}).(bool)
	return v
}

// budget counts requests against a hard limit, with a separate allowance for
// cleanup. A zero limit means unlimited, which only tests use: the CLI always
// sets one.
type budget struct {
	mu        sync.Mutex
	limit     int
	allowance int
	used      int
	cleanup   int
}

func newBudget(limit, cleanupAllowance int) *budget {
	if limit <= 0 {
		return nil
	}
	if cleanupAllowance < 0 {
		cleanupAllowance = 0
	}
	return &budget{limit: limit, allowance: cleanupAllowance}
}

// take reserves one request, or refuses it.
func (b *budget) take(cleanup bool) error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used < b.limit {
		b.used++
		return nil
	}
	if cleanup && b.cleanup < b.allowance {
		b.cleanup++
		return nil
	}
	return &ErrBudgetExceeded{Limit: b.limit, Cleanup: cleanup}
}

// BudgetUsage reports how many requests were counted against the budget and
// against the cleanup allowance.
type BudgetUsage struct {
	Limit            int
	Used             int
	CleanupAllowance int
	CleanupUsed      int
}

// Usage returns what the budget has counted so far. The zero value means no
// budget is configured.
func (c *Client) Usage() BudgetUsage {
	b := c.budget
	if b == nil {
		return BudgetUsage{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return BudgetUsage{Limit: b.limit, Used: b.used, CleanupAllowance: b.allowance, CleanupUsed: b.cleanup}
}
