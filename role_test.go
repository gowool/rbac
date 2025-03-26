package rbac

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultRole_Name(t *testing.T) {
	role := NewRole("test")
	assert.Equal(t, "test", role.Name())
}

func TestDefaultRole_AddPermissions(t *testing.T) {
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

func TestDefaultRole_AddChild(t *testing.T) {
	foo := NewRole("foo")
	bar := NewRole("bar")
	baz := NewRole("baz")

	assert.Nil(t, foo.AddChild(bar))
	assert.Nil(t, foo.AddChild(baz))
	assert.ElementsMatch(t, []Role{bar, baz}, foo.Children())
}

func TestDefaultRole_AddParent(t *testing.T) {
	foo := NewRole("foo")
	bar := NewRole("bar")
	baz := NewRole("baz")

	assert.Nil(t, foo.AddParent(bar))
	assert.Nil(t, foo.AddParent(baz))
	assert.ElementsMatch(t, []Role{bar, baz}, foo.Parents())
}

func TestDefaultRole_PermissionHierarchy(t *testing.T) {
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

func TestDefaultRole_CircleReferenceWithChild(t *testing.T) {
	foo := NewRole("foo")
	bar := NewRole("bar")
	baz := NewRole("baz")
	baz.AddPermissions("baz")

	assert.Nil(t, foo.AddChild(bar))
	assert.Nil(t, bar.AddChild(baz))
	assert.ErrorIs(t, baz.AddChild(foo), ErrCircularReference)
}

func TestDefaultRole_CircleReferenceWithParent(t *testing.T) {
	foo := NewRole("foo")
	bar := NewRole("bar")
	baz := NewRole("baz")
	baz.AddPermissions("baz")

	assert.Nil(t, foo.AddParent(bar))
	assert.Nil(t, bar.AddParent(baz))
	assert.ErrorIs(t, baz.AddParent(foo), ErrCircularReference)
}

func TestDefaultRole_Permissions(t *testing.T) {
	foo := NewRole("foo")
	foo.AddPermissions("foo.permission", "foo.2nd-permission")

	bar := NewRole("bar")
	bar.AddPermissions("bar.permission")

	baz := NewRole("baz")
	baz.AddPermissions("baz.permission")

	assert.Nil(t, foo.AddParent(bar))
	assert.Nil(t, foo.AddChild(baz))

	expected := []string{"foo.permission", "foo.2nd-permission", "bar.permission", "baz.permission"}
	assert.ElementsMatch(t, expected, bar.Permissions(true))

	assert.ElementsMatch(t, []string{"bar.permission"}, bar.Permissions(false))

	expected = []string{"foo.permission", "foo.2nd-permission", "baz.permission"}
	assert.ElementsMatch(t, expected, foo.Permissions(true))

	expected = []string{"foo.permission", "foo.2nd-permission"}
	assert.ElementsMatch(t, expected, foo.Permissions(false))

	assert.ElementsMatch(t, []string{"baz.permission"}, baz.Permissions(true))
	assert.ElementsMatch(t, []string{"baz.permission"}, baz.Permissions(false))
}

func TestDefaultRole_AddSameParent(t *testing.T) {
	foo := NewRole("foo")
	bar := NewRole("bar")

	assert.Nil(t, foo.AddParent(bar))
	assert.Nil(t, foo.AddParent(bar))

	assert.ElementsMatch(t, []Role{bar}, foo.Parents())
}
