package rbac

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
)

var ErrDeny = errors.New("deny")

type (
	claimsKey     struct{}
	assertionsKey struct{}
)

type Subject interface {
	Identifier() string
	Roles() []string
}

type Claims struct {
	Subject  Subject
	Metadata map[string]any
}

func WithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsKey{}, claims)
}

func CtxClaims(ctx context.Context) *Claims {
	claims, _ := ctx.Value(claimsKey{}).(*Claims)
	return claims
}

func WithAssertions(ctx context.Context, assertions ...Assertion) context.Context {
	return context.WithValue(ctx, assertionsKey{}, assertions)
}

func CtxAssertions(ctx context.Context) []Assertion {
	assertions, _ := ctx.Value(assertionsKey{}).([]Assertion)
	return append(make([]Assertion, 0, len(assertions)), assertions...)
}

type Target struct {
	Action     string
	Assertions []Assertion
	Metadata   map[string]any
}

type Decision int8

const (
	DecisionDeny = iota + 1
	DecisionAllow
)

func (d Decision) String() string {
	switch d {
	case DecisionDeny:
		return "deny"
	case DecisionAllow:
		return "allow"
	default:
		return "unknown"
	}
}

type Authorizer interface {
	Authorize(ctx context.Context, claims *Claims, target *Target) (Decision, error)
}

type DefaultAuthorizer struct {
	rbac *RBAC
}

func NewDefaultAuthorizer(rbac *RBAC) *DefaultAuthorizer {
	return &DefaultAuthorizer{rbac: rbac}
}

func (a *DefaultAuthorizer) Authorize(ctx context.Context, claims *Claims, target *Target) (d Decision, err error) {
	d = DecisionDeny
	err = ErrDeny

	if target == nil || target.Action == "" {
		return
	}

	if claims == nil || claims.Subject == nil {
		return
	}

	roles := make([]string, 0, len(claims.Subject.Roles())+1)
	roles = append(roles, claims.Subject.Identifier())
	roles = append(roles, claims.Subject.Roles()...)

	for _, role := range roles {
		granted, err1 := a.rbac.IsGrantedE(ctx, role, target.Action, target.Assertions...)
		if granted && err1 == nil {
			return DecisionAllow, nil
		}
		err = errors.Join(err, err1)
	}
	return
}

func RequestAuthorizer(authorizer Authorizer, actions func(*http.Request) []string) func(*http.Request) error {
	if actions == nil {
		actions = defaultActions
	}

	pool := &sync.Pool{
		New: func() any {
			return new(Target)
		},
	}

	return func(r *http.Request) (err error) {
		var decision Decision = DecisionDeny
		defer func() {
			if decision == DecisionDeny && err == nil {
				err = ErrDeny
			}
		}()

		ctx := r.Context()
		claims := CtxClaims(ctx)
		assertions := CtxAssertions(ctx)

		target := pool.Get().(*Target)
		defer pool.Put(target)

		for _, action := range actions(r) {
			target.Action = action
			target.Assertions = assertions

			if decision, err = authorizer.Authorize(ctx, claims, target); decision == DecisionAllow {
				return nil
			}
		}
		return
	}
}

func defaultActions(r *http.Request) []string {
	method, path := r.Method, r.URL.Path
	if path == "" {
		path = "/"
	}
	return []string{
		"*",
		method,
		path,
		fmt.Sprintf("%s %s", method, path),
	}
}
