package rbac

import (
	"fmt"
	"iter"
	"maps"
	"regexp"
	"sync"
)

var _ fmt.Stringer = (*Role)(nil)

var perms = new(sync.Map)

type Role struct {
	name        string
	permissions map[string]*regexp.Regexp
	parents     map[string]*Role
	children    map[string]*Role
}

func NewRole(name string) *Role {
	return &Role{
		name:        name,
		permissions: map[string]*regexp.Regexp{},
		parents:     map[string]*Role{},
		children:    map[string]*Role{},
	}
}

func (r *Role) String() string {
	return r.Name()
}

func (r *Role) Name() string {
	return r.name
}

func (r *Role) AddPermissions(permissions ...string) {
	for _, permission := range permissions {
		var re *regexp.Regexp
		if value, ok := perms.Load(permission); ok {
			re, _ = value.(*regexp.Regexp)
		} else {
			re, _ = regexp.Compile(permission)
			perms.Store(permission, re)
		}

		r.permissions[permission] = re
	}
}

func (r *Role) HasPermission(permission string) bool {
	if _, ok := r.permissions[permission]; ok {
		return true
	}

	for _, re := range r.permissions {
		if re != nil && re.MatchString(permission) {
			return true
		}
	}

	for child := range r.Children() {
		if child.HasPermission(permission) {
			return true
		}
	}

	return false
}

func (r *Role) Permissions(children bool) iter.Seq[string] {
	return func(yield func(string) bool) {
		_ = iterPermissions(r, children, yield)
	}
}

func iterPermissions(r *Role, children bool, yield func(string) bool) bool {
	for permission := range r.permissions {
		if !yield(permission) {
			return false
		}
	}

	if children {
		for child := range r.Children() {
			if !iterPermissions(child, children, yield) {
				return false
			}
		}
	}

	return true
}

func (r *Role) AddParent(parent *Role) error {
	if parent == nil {
		panic(ErrRoleNil)
	}

	if _, ok := r.parents[parent.Name()]; ok {
		return nil
	}

	if r.HasDescendant(parent) {
		return fmt.Errorf(`%w: to prevent circular references, you cannot add role "%s" as parent`, ErrCircularRef, parent.Name())
	}

	r.parents[parent.Name()] = parent

	return parent.AddChild(r)
}

func (r *Role) Parents() iter.Seq[*Role] {
	return maps.Values(r.parents)
}

func (r *Role) AddChild(child *Role) error {
	if child == nil {
		panic(ErrRoleNil)
	}

	if _, ok := r.children[child.Name()]; ok {
		return nil
	}

	if r.HasAncestor(child) {
		return fmt.Errorf(`%w: to prevent circular references, you cannot add role "%s" as child`, ErrCircularRef, child.Name())
	}

	r.children[child.Name()] = child

	return child.AddParent(r)
}

func (r *Role) Children() iter.Seq[*Role] {
	return maps.Values(r.children)
}

func (r *Role) HasAncestor(role *Role) bool {
	if role == nil {
		panic(ErrRoleNil)
	}

	if _, ok := r.parents[role.Name()]; ok {
		return true
	}

	for _, parent := range r.parents {
		if parent.HasAncestor(role) {
			return true
		}
	}

	return false
}

func (r *Role) HasDescendant(role *Role) bool {
	if role == nil {
		panic(ErrRoleNil)
	}

	if _, ok := r.children[role.Name()]; ok {
		return true
	}

	for _, child := range r.children {
		if child.HasDescendant(role) {
			return true
		}
	}

	return false
}
