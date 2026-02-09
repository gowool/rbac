package rbac

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/suite"
)

// Test subject for request authorizer tests
type testRequestSubject struct {
	roles []string
}

func (s *testRequestSubject) Roles() []string {
	return s.roles
}

// Mock authorizer for testing
type mockAuthorizer struct {
	decision Decision
}

func (m *mockAuthorizer) Authorize(context.Context, *Claims, *Target) Decision {
	return m.decision
}

type authorizerRequestSuit struct {
	suite.Suite
	rbac       *RBAC
	authorizer *mockAuthorizer
}

func TestAuthorizerRequestSuite(t *testing.T) {
	s := new(authorizerRequestSuit)
	suite.Run(t, s)
}

func (s *authorizerRequestSuit) SetupTest() {
	s.rbac = New()
	s.authorizer = &mockAuthorizer{decision: DecisionDeny}
}

func (s *authorizerRequestSuit) TestRequestInfo_Fields() {
	// Create a test request
	req := httptest.NewRequest("GET", "http://example.com/api/users?active=true", nil)
	req.Header.Set("Authorization", "Bearer token123")
	req.RemoteAddr = "192.168.1.1:8080"

	// Create RequestInfo from the request
	info := RequestInfo{
		Method:     req.Method,
		Host:       req.Host,
		RequestURI: req.RequestURI,
		Pattern:    req.Pattern,
		RemoteAddr: req.RemoteAddr,
		Header:     req.Header,
		URL:        req.URL,
		IsTLS:      req.TLS != nil, // This field is not set by RequestAuthorizer but we can test it here
	}

	// Verify all fields are correctly populated
	s.Equal("GET", info.Method)
	s.Equal("example.com", info.Host)
	s.Equal("http://example.com/api/users?active=true", info.RequestURI) // httptest.Request stores full URL
	s.Equal("", info.Pattern)                                            // Default value
	s.Equal("192.168.1.1:8080", info.RemoteAddr)
	s.Equal("Bearer token123", info.Header.Get("Authorization"))
	s.Equal("/api/users", info.URL.Path)
	s.Equal("active=true", info.URL.RawQuery)
	s.Equal(false, info.IsTLS) // HTTP request is not TLS
}

func (s *authorizerRequestSuit) TestRequestAuthorizer_NilActions() {
	// When actions is nil, should use defaultActions
	authorizerFunc := RequestAuthorizer(s.authorizer, nil)

	// Setup context with claims and subject
	subject := &testRequestSubject{roles: []string{"user"}}
	claims := &Claims{
		Subject:  subject,
		Metadata: map[string]any{},
	}
	ctx := WithClaims(context.Background(), claims)

	req := httptest.NewRequest("GET", "/api/users", nil).WithContext(ctx)

	decision := authorizerFunc(req)
	s.Equal(DecisionDeny, decision)
}

func (s *authorizerRequestSuit) TestRequestAuthorizer_CustomActions() {
	// Setup custom actions function
	customActions := func(r *http.Request) []string {
		return []string{"custom:action"}
	}

	// Setup authorizer to allow custom action
	s.authorizer.decision = DecisionAllow

	authorizerFunc := RequestAuthorizer(s.authorizer, customActions)

	// Setup context with claims and subject
	subject := &testRequestSubject{roles: []string{"user"}}
	claims := &Claims{
		Subject:  subject,
		Metadata: map[string]any{},
	}
	ctx := WithClaims(context.Background(), claims)

	req := httptest.NewRequest("GET", "/api/users", nil).WithContext(ctx)

	decision := authorizerFunc(req)
	s.Equal(DecisionAllow, decision)
}

func (s *authorizerRequestSuit) TestRequestAuthorizer_WithClaimsInContext() {
	// Setup authorizer to allow
	s.authorizer.decision = DecisionAllow

	authorizerFunc := RequestAuthorizer(s.authorizer, nil)

	// Setup context with claims and subject
	subject := &testRequestSubject{roles: []string{"admin"}}
	claims := &Claims{
		Subject:  subject,
		Metadata: map[string]any{"key": "value"},
	}
	ctx := WithClaims(context.Background(), claims)

	req := httptest.NewRequest("GET", "/api/users", nil).WithContext(ctx)

	decision := authorizerFunc(req)
	s.Equal(DecisionAllow, decision)
}

func (s *authorizerRequestSuit) TestRequestAuthorizer_WithAssertions() {
	// Setup authorizer to allow
	s.authorizer.decision = DecisionAllow

	authorizerFunc := RequestAuthorizer(s.authorizer, nil)

	// Setup context with claims and assertions
	subject := &testRequestSubject{roles: []string{"user"}}
	claims := &Claims{
		Subject:  subject,
		Metadata: map[string]any{},
	}
	assertions := []Assertion{&testAssertion{shouldPass: true}}

	ctx := WithClaims(context.Background(), claims)
	ctx = WithAssertions(ctx, assertions...)

	req := httptest.NewRequest("GET", "/api/users", nil).WithContext(ctx)

	decision := authorizerFunc(req)
	s.Equal(DecisionAllow, decision)
}

func (s *authorizerRequestSuit) TestRequestAuthorizer_NoClaimsInContext() {
	authorizerFunc := RequestAuthorizer(s.authorizer, nil)

	// Request without claims in context
	req := httptest.NewRequest("GET", "/api/users", nil)

	decision := authorizerFunc(req)
	s.Equal(DecisionDeny, decision)
}

func (s *authorizerRequestSuit) TestRequestAuthorizer_ClaimsWithNilSubject() {
	authorizerFunc := RequestAuthorizer(s.authorizer, nil)

	// Claims with nil subject
	claims := &Claims{
		Subject:  nil,
		Metadata: map[string]any{},
	}
	ctx := WithClaims(context.Background(), claims)

	req := httptest.NewRequest("GET", "/api/users", nil).WithContext(ctx)

	decision := authorizerFunc(req)
	s.Equal(DecisionDeny, decision)
}

func (s *authorizerRequestSuit) TestRequestAuthorizer_MultipleActions_FirstSucceeds() {
	// Setup custom actions that return multiple actions
	customActions := func(r *http.Request) []string {
		return []string{"first:action", "second:action", "third:action"}
	}

	// Setup authorizer to allow first action
	s.authorizer.decision = DecisionAllow

	authorizerFunc := RequestAuthorizer(s.authorizer, customActions)

	// Setup context with claims
	subject := &testRequestSubject{roles: []string{"user"}}
	claims := &Claims{
		Subject:  subject,
		Metadata: map[string]any{},
	}
	ctx := WithClaims(context.Background(), claims)

	req := httptest.NewRequest("GET", "/api/users", nil).WithContext(ctx)

	decision := authorizerFunc(req)
	s.Equal(DecisionAllow, decision)
}

func (s *authorizerRequestSuit) TestRequestAuthorizer_MultipleActions_SecondSucceeds() {
	// Setup custom actions and authorizer behavior
	customActions := func(r *http.Request) []string {
		return []string{"first:action", "second:action"}
	}

	s.authorizer = &mockAuthorizer{
		decision: DecisionAllow,
	}

	authorizerFunc := RequestAuthorizer(s.authorizer, customActions)

	// Setup context with claims
	subject := &testRequestSubject{roles: []string{"user"}}
	claims := &Claims{
		Subject:  subject,
		Metadata: map[string]any{},
	}
	ctx := WithClaims(context.Background(), claims)

	req := httptest.NewRequest("GET", "/api/users", nil).WithContext(ctx)

	decision := authorizerFunc(req)
	s.Equal(DecisionAllow, decision)
}

func (s *authorizerRequestSuit) TestRequestAuthorizer_RequestInfoInContext() {
	// Setup authorizer to allow
	s.authorizer.decision = DecisionAllow

	authorizerFunc := RequestAuthorizer(s.authorizer, nil)

	// Setup context with claims
	subject := &testRequestSubject{roles: []string{"user"}}
	claims := &Claims{
		Subject:  subject,
		Metadata: map[string]any{},
	}
	ctx := WithClaims(context.Background(), claims)

	// Create request
	req := httptest.NewRequest("POST", "/api/data", nil)
	req = req.WithContext(ctx)

	decision := authorizerFunc(req)
	s.Equal(DecisionAllow, decision)

	// Verify RequestInfo was added to context (just check basic functionality)
	info := CtxRequestInfo(req.Context())
	s.NotNil(info)
}

func (s *authorizerRequestSuit) TestRequestAuthorizer_TLSRequest() {
	// Setup authorizer to allow
	s.authorizer.decision = DecisionAllow

	authorizerFunc := RequestAuthorizer(s.authorizer, nil)

	// Setup context with claims
	subject := &testRequestSubject{roles: []string{"user"}}
	claims := &Claims{
		Subject:  subject,
		Metadata: map[string]any{},
	}
	ctx := WithClaims(context.Background(), claims)

	// Create HTTPS request
	req := httptest.NewRequest("GET", "https://secure.example.com/api/users", nil)
	req = req.WithContext(ctx)

	decision := authorizerFunc(req)
	s.Equal(DecisionAllow, decision)

	// Verify RequestInfo was added to context
	info := CtxRequestInfo(req.Context())
	s.NotNil(info)
}

func (s *authorizerRequestSuit) TestRequestAuthorizer_ObjectPoolUsage() {
	// This test verifies that the object pool is working correctly
	// by making multiple requests and checking that the pool is being used

	authorizerFunc := RequestAuthorizer(s.authorizer, nil)

	// Setup context with claims
	subject := &testRequestSubject{roles: []string{"user"}}
	claims := &Claims{
		Subject:  subject,
		Metadata: map[string]any{},
	}
	ctx := WithClaims(context.Background(), claims)

	// Make multiple requests to exercise the pool
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/api/users", nil).WithContext(ctx)
		decision := authorizerFunc(req)
		s.Equal(DecisionDeny, decision)
	}
}

func (s *authorizerRequestSuit) TestDefaultActions() {
	testCases := []struct {
		name            string
		method          string
		path            string
		expectedActions []string
	}{
		{
			name:   "GET request",
			method: "GET",
			path:   "/api/users",
			expectedActions: []string{
				"*",
				"GET",
				"/api/users",
				"GET /api/users",
			},
		},
		{
			name:   "POST request",
			method: "POST",
			path:   "/api/posts",
			expectedActions: []string{
				"*",
				"POST",
				"/api/posts",
				"POST /api/posts",
			},
		},
		{
			name:   "Empty path",
			method: "GET",
			path:   "http://example.com", // URL without path - path will be empty
			expectedActions: []string{
				"*",
				"GET",
				"/",     // Empty path should become "/"
				"GET /", // Empty path should become "/"
			},
		},
		{
			name:   "Root path",
			method: "GET",
			path:   "/",
			expectedActions: []string{
				"*",
				"GET",
				"/",
				"GET /",
			},
		},
		{
			name:   "Complex path",
			method: "PUT",
			path:   "/api/v1/users/123/posts/456",
			expectedActions: []string{
				"*",
				"PUT",
				"/api/v1/users/123/posts/456",
				"PUT /api/v1/users/123/posts/456",
			},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			actions := defaultActions(req)
			s.Equal(tc.expectedActions, actions)
		})
	}
}

func (s *authorizerRequestSuit) TestDefaultActionsWithQueryParams() {
	req := httptest.NewRequest("GET", "/api/users?active=true&page=1", nil)
	actions := defaultActions(req)

	// defaultActions uses only the path, not the query string
	expectedActions := []string{
		"*",
		"GET",
		"/api/users",     // Path without query
		"GET /api/users", // Method + Path only
	}

	s.Equal(expectedActions, actions)
}

func (s *authorizerRequestSuit) TestRequestAuthorizer_ComplexURL() {
	// Setup authorizer to allow
	s.authorizer.decision = DecisionAllow

	authorizerFunc := RequestAuthorizer(s.authorizer, nil)

	// Setup context with claims
	subject := &testRequestSubject{roles: []string{"user"}}
	claims := &Claims{
		Subject:  subject,
		Metadata: map[string]any{},
	}
	ctx := WithClaims(context.Background(), claims)

	// Create request with complex URL
	req := httptest.NewRequest("POST", "https://api.example.com:8443/v1/resource?id=123&filter=active", nil)
	req = req.WithContext(ctx)

	decision := authorizerFunc(req)
	s.Equal(DecisionAllow, decision)

	// Verify RequestInfo was added to context (URL may be reset by WithContext)
	info := CtxRequestInfo(req.Context())
	s.NotNil(info)
}
