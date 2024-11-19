package rbac

import (
	"context"
	"testing"

	"github.com/stretchr/testify/suite"
)

type testRole struct {
	Role
}

type simpleTrueAssertion struct{}

func (*simpleTrueAssertion) Assert(context.Context, Role, string) (bool, error) {
	return true, nil
}

type simpleFalseAssertion struct{}

func (*simpleFalseAssertion) Assert(context.Context, Role, string) (bool, error) {
	return false, nil
}

type roleMustMatchAssertion struct{}

func (*roleMustMatchAssertion) Assert(_ context.Context, role Role, _ string) (bool, error) {
	return role.Name() == "foo", nil
}

type rbacSuit struct {
	suite.Suite
	rbac *RBAC
}

func TestRBACSuite(t *testing.T) {
	s := new(rbacSuit)
	suite.Run(t, s)
}

func (s *rbacSuit) SetupTest() {
	s.rbac = New()
}

func (s *rbacSuit) TestIsGrantedAssertion() {
	foo := NewRole("foo")
	bar := NewRole("bar")

	_true := new(simpleTrueAssertion)
	_false := new(simpleFalseAssertion)

	roleNoMatch := new(roleMustMatchAssertion)
	roleMatch := new(roleMustMatchAssertion)

	foo.AddPermissions("can.foo")
	bar.AddPermissions("can.bar")

	s.Nil(s.rbac.AddRole(foo))
	s.Nil(s.rbac.AddRole(bar))

	s.True(s.rbac.IsGranted(context.Background(), foo, "can.foo", _true))
	s.False(s.rbac.IsGranted(context.Background(), bar, "can.bar", _false))

	s.False(s.rbac.IsGranted(context.Background(), foo, "cannot", _true))
	s.False(s.rbac.IsGranted(context.Background(), bar, "cannot", _false))

	s.False(s.rbac.IsGranted(context.Background(), bar, "can.bar", roleNoMatch))
	s.False(s.rbac.IsGranted(context.Background(), bar, "can.foo", roleNoMatch))

	s.True(s.rbac.IsGranted(context.Background(), foo, "can.foo", roleMatch))
}

func (s *rbacSuit) TestIsGrantedSingleRole() {
	foo := NewRole("foo")
	foo.AddPermissions("can.bar")

	s.Nil(s.rbac.AddRole(foo))

	s.True(s.rbac.IsGranted(context.Background(), "foo", "can.bar"))
	s.False(s.rbac.IsGranted(context.Background(), "foo", "can.baz"))
}

func (s *rbacSuit) TestIsGrantedChildRoles() {
	foo := NewRole("foo")
	bar := NewRole("bar")

	foo.AddPermissions("can.foo")
	bar.AddPermissions("can.bar")

	s.Nil(s.rbac.AddRole(foo))
	s.Nil(s.rbac.AddRole(bar, foo))

	s.True(s.rbac.IsGranted(context.Background(), "foo", "can.bar"))
	s.True(s.rbac.IsGranted(context.Background(), "foo", "can.foo"))
	s.True(s.rbac.IsGranted(context.Background(), "bar", "can.bar"))

	s.False(s.rbac.IsGranted(context.Background(), "foo", "can.baz"))
	s.False(s.rbac.IsGranted(context.Background(), "bar", "can.baz"))
}

func (s *rbacSuit) TestIsGrantedWithInvalidRole() {
	granted, err := s.rbac.IsGrantedE(context.Background(), "foo", "permission")

	s.False(granted)
	s.ErrorIs(err, ErrRoleNotFound)
}

func (s *rbacSuit) TestHasRole() {
	foo := NewRole("foo")
	snafu := testRole{Role: NewRole("snafu")}

	s.Nil(s.rbac.AddRole("bar"))
	s.Nil(s.rbac.AddRole(foo))
	s.Nil(s.rbac.AddRole("snafu"))

	s.True(s.rbac.HasRole(foo))
	s.True(s.rbac.HasRole("bar"))

	s.False(s.rbac.HasRole("baz"))

	roleSnafu, err := s.rbac.Role("snafu")

	s.NoError(err)
	s.NotNil(roleSnafu)
	s.NotEqual(snafu, roleSnafu)

	s.True(s.rbac.HasRole("snafu"))
	s.False(s.rbac.HasRole(snafu))
}

func (s *rbacSuit) TestAddRoleWithParentsUsingRBAC() {
	foo := NewRole("foo")
	bar := NewRole("bar")

	s.Nil(s.rbac.AddRole(foo))
	s.Nil(s.rbac.AddRole(bar, foo))

	s.ElementsMatch([]Role{foo}, bar.Parents())
	s.ElementsMatch([]Role{bar}, foo.Children())
}

func (s *rbacSuit) TestAddRoleWithAutomaticParentsUsingRBAC() {
	foo := NewRole("foo")
	bar := NewRole("bar")

	s.rbac.SetCreateMissingRoles(true)
	s.True(s.rbac.CreateMissingRoles())

	s.Nil(s.rbac.AddRole(bar, foo))

	s.ElementsMatch([]Role{foo}, bar.Parents())
	s.ElementsMatch([]Role{bar}, foo.Children())
}

func (s *rbacSuit) TestAddMultipleParentRole() {
	adminRole := NewRole("Administrator")
	adminRole.AddPermissions("user.manage")
	s.Nil(s.rbac.AddRole(adminRole))

	managerRole := NewRole("Manager")
	managerRole.AddPermissions("post.publish")
	s.Nil(s.rbac.AddRole(managerRole, "Administrator"))

	editorRole := NewRole("Editor")
	editorRole.AddPermissions("post.edit")
	s.Nil(s.rbac.AddRole(editorRole))

	viewerRole := NewRole("Viewer")
	viewerRole.AddPermissions("post.view")
	s.Nil(s.rbac.AddRole(viewerRole, "Editor", "Manager"))

	s.Equal("Viewer", editorRole.Children()[0].Name())
	s.Equal("Viewer", managerRole.Children()[0].Name())
	s.True(s.rbac.IsGranted(context.Background(), "Editor", "post.view"))
	s.True(s.rbac.IsGranted(context.Background(), "Manager", "post.view"))

	s.ElementsMatch([]Role{editorRole, managerRole}, viewerRole.Parents())
	s.ElementsMatch([]Role{adminRole}, managerRole.Parents())

	s.Empty(editorRole.Parents())
	s.Empty(adminRole.Parents())
}

func (s *rbacSuit) TestAddParentRole() {
	adminRole := NewRole("Administrator")
	adminRole.AddPermissions("user.manage")
	s.Nil(s.rbac.AddRole(adminRole))

	managerRole := NewRole("Manager")
	managerRole.AddPermissions("post.publish")
	s.Nil(managerRole.AddParent(adminRole))
	s.Nil(s.rbac.AddRole(managerRole))

	editorRole := NewRole("Editor")
	editorRole.AddPermissions("post.edit")
	s.Nil(s.rbac.AddRole(editorRole))

	viewerRole := NewRole("Viewer")
	viewerRole.AddPermissions("post.view")
	s.Nil(viewerRole.AddParent(editorRole))
	s.Nil(viewerRole.AddParent(managerRole))
	s.Nil(s.rbac.AddRole(viewerRole))

	s.ElementsMatch([]Role{viewerRole}, editorRole.Children())
	s.ElementsMatch([]Role{viewerRole}, managerRole.Children())
	s.ElementsMatch([]Role{editorRole, managerRole}, viewerRole.Parents())
	s.ElementsMatch([]Role{adminRole}, managerRole.Parents())

	s.Empty(editorRole.Parents())
	s.Empty(adminRole.Parents())

	s.True(s.rbac.IsGranted(context.Background(), "Editor", "post.view"))
	s.True(s.rbac.IsGranted(context.Background(), "Editor", "post.edit"))
	s.True(s.rbac.IsGranted(context.Background(), "Administrator", "post.view"))
	s.True(s.rbac.IsGranted(context.Background(), "Administrator", "post.publish"))
	s.False(s.rbac.IsGranted(context.Background(), "Administrator", "post.edit"))
	s.True(s.rbac.IsGranted(context.Background(), "Manager", "post.view"))
	s.False(s.rbac.IsGranted(context.Background(), "Manager", "post.edit"))
	s.False(s.rbac.IsGranted(context.Background(), "Manager", "user.manage"))
	s.True(s.rbac.IsGranted(context.Background(), "Viewer", "post.view"))
	s.False(s.rbac.IsGranted(context.Background(), "Viewer", "post.edit"))
	s.False(s.rbac.IsGranted(context.Background(), "Viewer", "post.publish"))
	s.False(s.rbac.IsGranted(context.Background(), "Viewer", "user.manage"))
	s.False(s.rbac.IsGranted(context.Background(), "Editor", "user.manage"))
	s.False(s.rbac.IsGranted(context.Background(), "Editor", "post.publish"))
}
