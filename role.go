package rbac

import (
	"errors"
	"fmt"
	"maps"
	"slices"
)

var ErrCircularReference = errors.New("circular reference detected")

type Role interface {
	fmt.Stringer
	Name() string
	AddPermissions(permission string, rest ...string)
	HasPermission(permission string) bool
	Permissions(children bool) []string
	AddParent(Role) error
	Parents() []Role
	AddChild(Role) error
	Children() []Role
	HasAncestor(role Role) bool
	HasDescendant(role Role) bool
}

type DefaultRole struct {
	name        string
	permissions map[string]struct{}
	parents     map[string]Role
	children    map[string]Role
}

func NewRole(name string) *DefaultRole {
	return &DefaultRole{
		name:        name,
		permissions: map[string]struct{}{},
		parents:     map[string]Role{},
		children:    map[string]Role{},
	}
}

func (r *DefaultRole) String() string {
	return r.Name()
}

func (r *DefaultRole) Name() string {
	return r.name
}

func (r *DefaultRole) AddPermissions(permission string, rest ...string) {
	r.permissions[permission] = struct{}{}
	for _, p := range rest {
		r.permissions[p] = struct{}{}
	}
}

func (r *DefaultRole) HasPermission(permission string) bool {
	if _, ok := r.permissions[permission]; ok {
		return true
	}

	for _, child := range r.children {
		if child.HasPermission(permission) {
			return true
		}
	}

	return false
}

func (r *DefaultRole) Permissions(children bool) []string {
	permissions := maps.Clone(r.permissions)
	if children {
		for _, child := range r.children {
			for _, permission := range child.Permissions(children) {
				permissions[permission] = struct{}{}
			}
		}
	}
	return slices.Collect(maps.Keys(permissions))
}

func (r *DefaultRole) AddParent(parent Role) error {
	if r.HasDescendant(parent) {
		return fmt.Errorf(`%w: to prevent circular references, you cannot add role "%s" as parent`, ErrCircularReference, parent.Name())
	}

	if _, ok := r.parents[parent.Name()]; ok {
		return nil
	}

	r.parents[parent.Name()] = parent
	return parent.AddChild(r)
}

func (r *DefaultRole) Parents() []Role {
	return slices.Collect(maps.Values(r.parents))
}

func (r *DefaultRole) AddChild(child Role) error {
	if r.HasAncestor(child) {
		return fmt.Errorf(`%w: to prevent circular references, you cannot add role "%s" as child`, ErrCircularReference, child.Name())
	}

	if _, ok := r.children[child.Name()]; ok {
		return nil
	}

	r.children[child.Name()] = child
	return child.AddParent(r)
}

func (r *DefaultRole) Children() []Role {
	return slices.Collect(maps.Values(r.children))
}

func (r *DefaultRole) HasAncestor(role Role) bool {
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

func (r *DefaultRole) HasDescendant(role Role) bool {
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
