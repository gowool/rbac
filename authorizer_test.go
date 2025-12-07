package rbac

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/suite"
)

// Test subjects for authorizer tests
type testSubject struct {
	roles []string
}

func (s *testSubject) Roles() []string {
	return s.roles
}

// Test assertions for authorizer tests
type testAssertion struct {
	shouldPass bool
	err        error
}

func (a *testAssertion) Assert(ctx context.Context, role Role, permission string) (bool, error) {
	return a.shouldPass, a.err
}

type failingAssertion struct{}

func (a *failingAssertion) Assert(ctx context.Context, role Role, permission string) (bool, error) {
	return false, errors.New("assertion failed")
}

type authorizerSuit struct {
	suite.Suite
	rbac       *RBAC
	authorizer *DefaultAuthorizer
}

func TestAuthorizerSuite(t *testing.T) {
	s := new(authorizerSuit)
	suite.Run(t, s)
}

func (s *authorizerSuit) SetupTest() {
	s.rbac = New()
	s.authorizer = NewDefaultAuthorizer(s.rbac)
}

func (s *authorizerSuit) TestNewDefaultAuthorizer() {
	rbac := New()
	authorizer := NewDefaultAuthorizer(rbac)

	s.NotNil(authorizer)
	s.Equal(rbac, authorizer.rbac)
}

func (s *authorizerSuit) TestAuthorize_ValidRequestWithPermission() {
	// Setup roles and permissions
	userRole := NewRole("user")
	userRole.AddPermissions("read:posts")

	s.Nil(s.rbac.AddRole(userRole))

	// Create subject with user role
	subject := &testSubject{
		roles: []string{"user"},
	}

	claims := &Claims{
		Subject:  subject,
		Metadata: map[string]any{},
	}

	target := &Target{
		Action:     "read:posts",
		Assertions: []Assertion{},
		Metadata:   map[string]any{},
	}

	decision, err := s.authorizer.Authorize(context.Background(), claims, target)

	s.Equal(Decision(DecisionAllow), decision)
	s.NoError(err)
}

func (s *authorizerSuit) TestAuthorize_ValidRequestWithoutPermission() {
	// Setup roles and permissions
	userRole := NewRole("user")
	userRole.AddPermissions("read:posts")

	s.Nil(s.rbac.AddRole(userRole))

	// Create subject with user role
	subject := &testSubject{
		roles: []string{"user"},
	}

	claims := &Claims{
		Subject:  subject,
		Metadata: map[string]any{},
	}

	target := &Target{
		Action:     "write:posts", // Different permission
		Assertions: []Assertion{},
		Metadata:   map[string]any{},
	}

	decision, err := s.authorizer.Authorize(context.Background(), claims, target)

	s.Equal(Decision(DecisionDeny), decision)
	s.ErrorIs(err, ErrDeny)
}

func (s *authorizerSuit) TestAuthorize_MultipleRoles() {
	// Setup roles
	userRole := NewRole("user")
	userRole.AddPermissions("read:posts")

	adminRole := NewRole("admin")
	adminRole.AddPermissions("delete:posts")

	s.Nil(s.rbac.AddRole(userRole))
	s.Nil(s.rbac.AddRole(adminRole))

	// Create subject with multiple roles
	subject := &testSubject{
		roles: []string{"user", "admin"},
	}

	claims := &Claims{
		Subject:  subject,
		Metadata: map[string]any{},
	}

	// Test admin permission
	target := &Target{
		Action:     "delete:posts",
		Assertions: []Assertion{},
		Metadata:   map[string]any{},
	}

	decision, err := s.authorizer.Authorize(context.Background(), claims, target)

	s.Equal(Decision(DecisionAllow), decision)
	s.NoError(err)
}

func (s *authorizerSuit) TestAuthorize_WithAssertions() {
	// Setup roles
	userRole := NewRole("user")
	userRole.AddPermissions("read:posts")

	s.Nil(s.rbac.AddRole(userRole))

	// Create subject
	subject := &testSubject{
		roles: []string{"user"},
	}

	claims := &Claims{
		Subject:  subject,
		Metadata: map[string]any{},
	}

	// Test with passing assertion
	target := &Target{
		Action:     "read:posts",
		Assertions: []Assertion{&testAssertion{shouldPass: true}},
		Metadata:   map[string]any{},
	}

	decision, err := s.authorizer.Authorize(context.Background(), claims, target)

	s.Equal(Decision(DecisionAllow), decision)
	s.NoError(err)

	// Test with failing assertion
	target.Assertions = []Assertion{&testAssertion{shouldPass: false}}

	decision, err = s.authorizer.Authorize(context.Background(), claims, target)

	s.Equal(Decision(DecisionDeny), decision)
	s.ErrorIs(err, ErrDeny)
}

func (s *authorizerSuit) TestAuthorize_WithAssertionError() {
	// Setup roles
	userRole := NewRole("user")
	userRole.AddPermissions("read:posts")

	s.Nil(s.rbac.AddRole(userRole))

	// Create subject
	subject := &testSubject{
		roles: []string{"user"},
	}

	claims := &Claims{
		Subject:  subject,
		Metadata: map[string]any{},
	}

	target := &Target{
		Action:     "read:posts",
		Assertions: []Assertion{&failingAssertion{}},
		Metadata:   map[string]any{},
	}

	decision, err := s.authorizer.Authorize(context.Background(), claims, target)

	s.Equal(Decision(DecisionDeny), decision)
	s.ErrorContains(err, "assertion failed")
}

func (s *authorizerSuit) TestAuthorize_MultipleRoles_FirstSucceeds() {
	// Setup roles
	userRole := NewRole("user")
	userRole.AddPermissions("read:posts")

	guestRole := NewRole("guest")
	// No permissions for guest

	s.Nil(s.rbac.AddRole(userRole))
	s.Nil(s.rbac.AddRole(guestRole))

	// Create subject with multiple roles - user first
	subject := &testSubject{
		roles: []string{"user", "guest"},
	}

	claims := &Claims{
		Subject:  subject,
		Metadata: map[string]any{},
	}

	target := &Target{
		Action:     "read:posts",
		Assertions: []Assertion{},
		Metadata:   map[string]any{},
	}

	decision, err := s.authorizer.Authorize(context.Background(), claims, target)

	s.Equal(Decision(DecisionAllow), decision)
	s.NoError(err)
}

func (s *authorizerSuit) TestAuthorize_MultipleRoles_SecondSucceeds() {
	// Setup roles
	userRole := NewRole("user")
	// No permissions for user

	adminRole := NewRole("admin")
	adminRole.AddPermissions("delete:posts")

	s.Nil(s.rbac.AddRole(userRole))
	s.Nil(s.rbac.AddRole(adminRole))

	// Create subject with multiple roles - admin second
	subject := &testSubject{
		roles: []string{"user", "admin"},
	}

	claims := &Claims{
		Subject:  subject,
		Metadata: map[string]any{},
	}

	target := &Target{
		Action:     "delete:posts",
		Assertions: []Assertion{},
		Metadata:   map[string]any{},
	}

	decision, err := s.authorizer.Authorize(context.Background(), claims, target)

	s.Equal(Decision(DecisionAllow), decision)
	s.NoError(err)
}

func (s *authorizerSuit) TestAuthorize_NilTarget() {
	subject := &testSubject{
		roles: []string{"user"},
	}

	claims := &Claims{
		Subject:  subject,
		Metadata: map[string]any{},
	}

	decision, err := s.authorizer.Authorize(context.Background(), claims, nil)

	s.Equal(Decision(DecisionDeny), decision)
	s.ErrorIs(err, ErrDeny)
}

func (s *authorizerSuit) TestAuthorize_TargetWithEmptyAction() {
	subject := &testSubject{
		roles: []string{"user"},
	}

	claims := &Claims{
		Subject:  subject,
		Metadata: map[string]any{},
	}

	target := &Target{
		Action:     "", // Empty action
		Assertions: []Assertion{},
		Metadata:   map[string]any{},
	}

	decision, err := s.authorizer.Authorize(context.Background(), claims, target)

	s.Equal(Decision(DecisionDeny), decision)
	s.ErrorIs(err, ErrDeny)
}

func (s *authorizerSuit) TestAuthorize_NilClaims() {
	target := &Target{
		Action:     "read:posts",
		Assertions: []Assertion{},
		Metadata:   map[string]any{},
	}

	decision, err := s.authorizer.Authorize(context.Background(), nil, target)

	s.Equal(Decision(DecisionDeny), decision)
	s.ErrorIs(err, ErrDeny)
}

func (s *authorizerSuit) TestAuthorize_ClaimsWithNilSubject() {
	claims := &Claims{
		Subject:  nil,
		Metadata: map[string]any{},
	}

	target := &Target{
		Action:     "read:posts",
		Assertions: []Assertion{},
		Metadata:   map[string]any{},
	}

	decision, err := s.authorizer.Authorize(context.Background(), claims, target)

	s.Equal(Decision(DecisionDeny), decision)
	s.ErrorIs(err, ErrDeny)
}

func (s *authorizerSuit) TestAuthorize_NonExistentRole() {
	subject := &testSubject{
		roles: []string{"nonexistent"},
	}

	claims := &Claims{
		Subject:  subject,
		Metadata: map[string]any{},
	}

	target := &Target{
		Action:     "read:posts",
		Assertions: []Assertion{},
		Metadata:   map[string]any{},
	}

	decision, err := s.authorizer.Authorize(context.Background(), claims, target)

	s.Equal(Decision(DecisionDeny), decision)
	s.ErrorIs(err, ErrDeny)
	s.ErrorContains(err, ErrRoleNotFound.Error())
}

func (s *authorizerSuit) TestAuthorize_EmptyRoles() {
	subject := &testSubject{
		roles: []string{}, // Empty roles
	}

	claims := &Claims{
		Subject:  subject,
		Metadata: map[string]any{},
	}

	target := &Target{
		Action:     "read:posts",
		Assertions: []Assertion{},
		Metadata:   map[string]any{},
	}

	decision, err := s.authorizer.Authorize(context.Background(), claims, target)

	s.Equal(Decision(DecisionDeny), decision)
	s.ErrorIs(err, ErrDeny)
}

func (s *authorizerSuit) TestDecisionString() {
	deny := Decision(DecisionDeny)
	allow := Decision(DecisionAllow)
	s.Equal("deny", deny.String())
	s.Equal("allow", allow.String())
	s.Equal("unknown", Decision(2).String()) // Invalid decision
}

func (s *authorizerSuit) TestTargetReset() {
	target := &Target{
		Action:     "test:action",
		Assertions: []Assertion{&testAssertion{shouldPass: true}},
		Metadata:   map[string]any{"key": "value"},
	}

	target.reset()

	s.Empty(target.Action)
	s.Nil(target.Assertions)
	s.Nil(target.Metadata)
}

func (s *authorizerSuit) TestAuthorize_WithContext() {
	ctx := context.Background()

	// Setup roles
	userRole := NewRole("user")
	userRole.AddPermissions("read:posts")

	s.Nil(s.rbac.AddRole(userRole))

	subject := &testSubject{
		roles: []string{"user"},
	}

	claims := &Claims{
		Subject:  subject,
		Metadata: map[string]any{},
	}

	target := &Target{
		Action:     "read:posts",
		Assertions: []Assertion{},
		Metadata:   map[string]any{},
	}

	decision, err := s.authorizer.Authorize(ctx, claims, target)

	s.Equal(Decision(DecisionAllow), decision)
	s.NoError(err)
}

func (s *authorizerSuit) TestAuthorize_MultipleErrorsJoined() {
	subject := &testSubject{
		roles: []string{"nonexistent1", "nonexistent2"},
	}

	claims := &Claims{
		Subject:  subject,
		Metadata: map[string]any{},
	}

	target := &Target{
		Action:     "read:posts",
		Assertions: []Assertion{&failingAssertion{}},
		Metadata:   map[string]any{},
	}

	decision, err := s.authorizer.Authorize(context.Background(), claims, target)

	s.Equal(Decision(DecisionDeny), decision)
	s.Error(err)
	// Should contain role not found errors
	s.Contains(err.Error(), ErrRoleNotFound.Error())
}
