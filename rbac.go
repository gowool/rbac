package rbac

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
)

var (
	ErrRoleNotFound = errors.New("role not found")
	ErrInvalidRole  = errors.New("role must be a string or implement the Role interface")
)

type Assertion interface {
	Assert(ctx context.Context, role Role, permission string) (bool, error)
}

type AssertionFunc func(ctx context.Context, role Role, permission string) (bool, error)

func (f AssertionFunc) Assert(ctx context.Context, role Role, permission string) (bool, error) {
	return f(ctx, role, permission)
}

type AuthorizationChecker interface {
	IsGranted(ctx context.Context, role any, permission string, assertions ...Assertion) bool
}

type RBAC struct {
	roles              map[string]Role
	createMissingRoles bool
}

func New() *RBAC {
	return &RBAC{roles: map[string]Role{}}
}

func (rbac *RBAC) SetCreateMissingRoles(createMissingRoles bool) *RBAC {
	rbac.createMissingRoles = createMissingRoles
	return rbac
}

func (rbac *RBAC) CreateMissingRoles() bool {
	return rbac.createMissingRoles
}

func (rbac *RBAC) Roles() []Role {
	return slices.Collect(maps.Values(rbac.roles))
}

func (rbac *RBAC) Role(name string) (Role, error) {
	if role, ok := rbac.roles[name]; ok {
		return role, nil
	}
	return nil, fmt.Errorf(`%w: no role with name "%s" could be found`, ErrRoleNotFound, name)
}

func (rbac *RBAC) HasRole(role any) (bool, error) {
	switch role := role.(type) {
	case string:
		_, ok := rbac.roles[role]
		return ok, nil
	case Role, *DefaultRole, DefaultRole:
		r, ok := rbac.roles[fmt.Sprintf("%s", role)]
		return ok && r == role, nil
	default:
		return false, ErrInvalidRole
	}
}

func (rbac *RBAC) AddRole(role any, parents ...any) error {
	var r Role
	switch role := role.(type) {
	case string:
		r = NewRole(role)
	case Role:
		r = role
	case DefaultRole:
		r = &role
	default:
		return ErrInvalidRole
	}

	for _, parent := range parents {
		if rbac.createMissingRoles {
			ok, err := rbac.HasRole(parent)
			if err != nil {
				return err
			}
			if !ok {
				if err = rbac.AddRole(parent); err != nil {
					return err
				}
			}
		}
		parentRole, err := rbac.Role(fmt.Sprintf("%s", parent))
		if err != nil {
			return err
		}
		if err = parentRole.AddChild(r); err != nil {
			return err
		}
	}

	rbac.roles[r.Name()] = r
	return nil
}

func (rbac *RBAC) IsGranted(ctx context.Context, role any, permission string, assertions ...Assertion) bool {
	granted, err := rbac.IsGrantedE(ctx, role, permission, assertions...)
	return granted && err == nil
}

func (rbac *RBAC) IsGrantedE(ctx context.Context, role any, permission string, assertions ...Assertion) (bool, error) {
	ok, err := rbac.HasRole(role)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, fmt.Errorf(`%w: no role with name "%s" could be found`, ErrRoleNotFound, role)
	}

	r, err := rbac.Role(fmt.Sprintf("%s", role))
	if err != nil {
		return false, err
	}

	if !r.HasPermission(permission) {
		return false, nil
	}

	for _, assertion := range assertions {
		if ok, err = assertion.Assert(ctx, r, permission); !ok || err != nil {
			return false, err
		}
	}

	return true, nil
}
