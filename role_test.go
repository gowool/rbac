package rbac

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRole_Name(t *testing.T) {
	role := NewRole("test")
	assert.Equal(t, "test", role.Name())
}

func TestRole_AddPermissions(t *testing.T) {
	role1 := NewRole("test")
	role1.AddPermissions("bar", "baz", "POST /api/v1/foo/\\d+$")
	assert.True(t, role1.HasPermission("bar"))
	assert.True(t, role1.HasPermission("baz"))
	assert.True(t, role1.HasPermission("POST /api/v1/foo/123"))
	assert.False(t, role1.HasPermission("GET /api/v1/foo/123"))
	assert.False(t, role1.HasPermission("POST /api/v1/foo/123/boo"))
	assert.False(t, role1.HasPermission("POST /api/v1/foo/boo"))

	role2 := NewRole("test2")
	role2.AddPermissions("*")
	assert.True(t, role2.HasPermission("*"))
	assert.False(t, role2.HasPermission("POST /api/v1/foo/boo"))

	role3 := NewRole("test3")
	role3.AddPermissions(".*")
	assert.True(t, role3.HasPermission("*"))
	assert.True(t, role3.HasPermission("POST /api/v1/foo/boo"))
}

func TestRole_AddChild(t *testing.T) {
	foo := NewRole("foo")
	bar := NewRole("bar")
	baz := NewRole("baz")

	assert.Nil(t, foo.AddChild(bar))
	assert.Nil(t, foo.AddChild(baz))
	assert.ElementsMatch(t, []*Role{bar, baz}, slices.Collect(foo.Children()))
}

func TestRole_AddParent(t *testing.T) {
	foo := NewRole("foo")
	bar := NewRole("bar")
	baz := NewRole("baz")

	assert.Nil(t, foo.AddParent(bar))
	assert.Nil(t, foo.AddParent(baz))
	assert.ElementsMatch(t, []*Role{bar, baz}, slices.Collect(foo.Parents()))
}

func TestRole_PermissionHierarchy(t *testing.T) {
	foo := NewRole("foo")
	foo.AddPermissions("foo.permission")

	bar := NewRole("bar")
	bar.AddPermissions("bar.permission")

	baz := NewRole("baz")
	baz.AddPermissions("baz.permission")

	assert.Nil(t, foo.AddParent(bar))
	assert.Nil(t, foo.AddChild(baz))

	assert.True(t, bar.HasPermission("bar.permission"))
	assert.True(t, bar.HasPermission("foo.permission"))
	assert.True(t, bar.HasPermission("baz.permission"))

	assert.False(t, foo.HasPermission("bar.permission"))
	assert.True(t, foo.HasPermission("foo.permission"))
	assert.True(t, foo.HasPermission("baz.permission"))

	assert.False(t, baz.HasPermission("bar.permission"))
	assert.False(t, baz.HasPermission("foo.permission"))
	assert.True(t, baz.HasPermission("baz.permission"))
}

func TestRole_CircleReferenceWithChild(t *testing.T) {
	foo := NewRole("foo")
	bar := NewRole("bar")
	baz := NewRole("baz")
	baz.AddPermissions("baz")

	assert.Nil(t, foo.AddChild(bar))
	assert.Nil(t, bar.AddChild(baz))
	assert.ErrorIs(t, baz.AddChild(foo), ErrCircularRef)
}

func TestRole_CircleReferenceWithParent(t *testing.T) {
	foo := NewRole("foo")
	bar := NewRole("bar")
	baz := NewRole("baz")
	baz.AddPermissions("baz")

	assert.Nil(t, foo.AddParent(bar))
	assert.Nil(t, bar.AddParent(baz))
	assert.ErrorIs(t, baz.AddParent(foo), ErrCircularRef)
}

func TestRole_Permissions(t *testing.T) {
	foo := NewRole("foo")
	foo.AddPermissions("foo.permission", "foo.2nd-permission")

	bar := NewRole("bar")
	bar.AddPermissions("bar.permission")

	baz := NewRole("baz")
	baz.AddPermissions("baz.permission")

	assert.Nil(t, foo.AddParent(bar))
	assert.Nil(t, foo.AddChild(baz))

	expected := []string{"foo.permission", "foo.2nd-permission", "bar.permission", "baz.permission"}
	assert.ElementsMatch(t, expected, slices.Collect(bar.Permissions(true)))

	assert.ElementsMatch(t, []string{"bar.permission"}, slices.Collect(bar.Permissions(false)))

	expected = []string{"foo.permission", "foo.2nd-permission", "baz.permission"}
	assert.ElementsMatch(t, expected, slices.Collect(foo.Permissions(true)))

	expected = []string{"foo.permission", "foo.2nd-permission"}
	assert.ElementsMatch(t, expected, slices.Collect(foo.Permissions(false)))

	assert.ElementsMatch(t, []string{"baz.permission"}, slices.Collect(baz.Permissions(true)))
	assert.ElementsMatch(t, []string{"baz.permission"}, slices.Collect(baz.Permissions(false)))
}

func TestRole_AddSameParent(t *testing.T) {
	foo := NewRole("foo")
	bar := NewRole("bar")

	assert.Nil(t, foo.AddParent(bar))
	assert.Nil(t, foo.AddParent(bar))

	assert.ElementsMatch(t, []*Role{bar}, slices.Collect(foo.Parents()))
}
