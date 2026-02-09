package rbac

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"maps"
)

var (
	ErrCircularRef  = errors.New("circular reference detected")
	ErrRoleNil      = errors.New("role is nil")
	ErrRoleNotFound = errors.New("role not found")
	ErrInvalidRole  = errors.New("role must be a string or implement the Role interface")
)

type Assertion interface {
	Assert(ctx context.Context, role *Role, permission string) bool
}

type AssertionFunc func(ctx context.Context, role *Role, permission string) bool

func (f AssertionFunc) Assert(ctx context.Context, role *Role, permission string) bool {
	return f(ctx, role, permission)
}

type AuthorizationChecker interface {
	IsGranted(ctx context.Context, role any, permission string, assertions ...Assertion) bool
}

type RBAC struct {
	roles              map[string]*Role
	createMissingRoles bool
}

func New() *RBAC {
	return &RBAC{roles: map[string]*Role{}}
}

func (rbac *RBAC) SetCreateMissingRoles(createMissingRoles bool) *RBAC {
	rbac.createMissingRoles = createMissingRoles
	return rbac
}

func (rbac *RBAC) CreateMissingRoles() bool {
	return rbac.createMissingRoles
}

func (rbac *RBAC) Roles() iter.Seq[*Role] {
	return maps.Values(rbac.roles)
}

func (rbac *RBAC) Role(name string) (*Role, error) {
	if role, ok := rbac.roles[name]; ok {
		return role, nil
	}
	return nil, fmt.Errorf(`%w: no role with name "%s" could be found`, ErrRoleNotFound, name)
}

func (rbac *RBAC) HasRole(role any) (bool, error) {
	name, err := rbac.roleName(role)
	if err != nil {
		return false, err
	}
	_, ok := rbac.roles[name]
	return ok, nil
}

func (rbac *RBAC) AddRole(role any, parents ...any) error {
	var r *Role
	switch role := role.(type) {
	case string:
		r = NewRole(role)
	case Role:
		r = &role
	case *Role:
		r = role
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

func (rbac *RBAC) IsGrantedE(ctx context.Context, role any, permission string, assertions ...Assertion) (granted bool, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			var ok bool
			if err, ok = rec.(error); !ok {
				err = fmt.Errorf("%v", rec)
			}
		}
	}()

	name, err := rbac.roleName(role)
	if err != nil {
		return false, err
	}

	r, ok := rbac.roles[name]
	if !ok {
		return false, fmt.Errorf(`%w: no role with name "%s" could be found`, ErrRoleNotFound, role)
	}

	if !r.HasPermission(permission) {
		return false, nil
	}

	for _, assertion := range assertions {
		if ok = assertion.Assert(ctx, r, permission); !ok {
			return false, nil
		}
	}

	return true, nil
}

func (rbac *RBAC) roleName(role any) (string, error) {
	switch role := role.(type) {
	case string:
		return role, nil
	case Role:
		return role.Name(), nil
	case *Role:
		return role.Name(), nil
	default:
		return "", ErrInvalidRole
	}
}
