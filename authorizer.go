package rbac

import (
	"context"
	"errors"
)

var ErrDeny = errors.New("deny")

type Subject interface {
	Roles() []string
}

type Claims struct {
	Subject  Subject
	Metadata map[string]any
}

type Target struct {
	Action     string
	Assertions []Assertion
	Metadata   map[string]any
}

func (t *Target) reset() {
	t.Action = ""
	t.Assertions = nil
	t.Metadata = nil
}

type Decision int8

const (
	DecisionDeny = iota
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

	for _, role := range claims.Subject.Roles() {
		granted, err1 := a.rbac.IsGrantedE(ctx, role, target.Action, target.Assertions...)
		if granted && err1 == nil {
			return DecisionAllow, nil
		}
		err = errors.Join(err, err1)
	}
	return
}
