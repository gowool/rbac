package rbac

import (
	"context"
	"errors"
)

var ErrDeny = errors.New("deny")

type Subject interface {
	Identifier() string
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
