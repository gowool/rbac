# RBAC (Role-Based Access Control)

A comprehensive and flexible Go library for implementing role-based access control with hierarchical roles, regex pattern support, and custom assertions.

## Features

- **Hierarchical Role Management**: Create parent-child role relationships with permission inheritance
- **Flexible Permission System**: Support for both exact string permissions and regex patterns
- **Custom Assertions**: Inject custom business logic into authorization decisions
- **Context-Aware**: Built-in support for request context and metadata
- **Performance Optimized**: Object pooling and efficient permission checking
- **Configuration-Based**: JSON/YAML configuration support for declarative setup
- **Circular Reference Protection**: Prevents infinite loops in role hierarchies

## Installation

```sh
go get -u github.com/gowool/rbac
```

## Quick Start

### Basic Usage

```go
package main

import (
    "context"
    "fmt"

    "github.com/gowool/rbac"
)

func main() {
    // Create RBAC instance
    r := rbac.New()

    // Create roles
    adminRole := rbac.NewRole("admin")
    userRole := rbac.NewRole("user")

    // Add roles to RBAC (user inherits from admin)
    r.AddRole(adminRole)
    r.AddRole(userRole, adminRole)

    // Add permissions
    adminRole.AddPermissions("user.create", "user.delete", "user.*")
    userRole.AddPermissions("user.view", "user.edit")

    // Check permissions
    fmt.Println(r.IsGranted(context.Background(), "admin", "user.create")) // true
    fmt.Println(r.IsGranted(context.Background(), "user", "user.create"))  // true (inherited)
    fmt.Println(r.IsGranted(context.Background(), "user", "user.view"))    // true
    fmt.Println(r.IsGranted(context.Background(), "user", "system.admin")) // false
}
```

### Configuration-Based Setup

```go
package main

import (
    "github.com/gowool/rbac"
)

func main() {
    config := rbac.Config{
        CreateMissingRoles: true,
        RoleHierarchy: []rbac.RoleConfig{
            {Role: "super_admin", Parents: []string{}},
            {Role: "admin", Parents: []string{"super_admin"}},
            {Role: "user", Parents: []string{"admin"}},
        },
        AccessControl: []rbac.AccessConfig{
            {Role: "super_admin", Permissions: []string{"*"}},
            {Role: "admin", Permissions: []string{"user.*", "post.*", "system.*"}},
            {Role: "user", Permissions: []string{"post.view", "post.create", "comment.*"}},
        },
    }

    rbac, err := rbac.NewWithConfig(config)
    if err != nil {
        panic(err)
    }

    // RBAC is now ready to use with all roles and permissions configured
}
```

## Core Concepts

### Roles

Roles are hierarchical entities that can have permissions and parent-child relationships:

```go
// Create a role
adminRole := rbac.NewRole("admin")

// Add permissions (exact strings and regex patterns)
adminRole.AddPermissions("user.create", "user.delete", "post:\\d+:edit")

// Create hierarchy
userRole := rbac.NewRole("user")
userRole.AddParent(adminRole) // user inherits admin permissions

// Check permissions
hasPermission := adminRole.HasPermission("user.create")
```

### Subjects

Subjects represent entities that can be authorized (users, services, etc.):

```go
type UserSubject struct {
    userID string
    roles  []string
}

func (u *UserSubject) Roles() []string {
    return u.roles
}

subject := &UserSubject{userID: "123", roles: []string{"user", "editor"}}
```

### Assertions

Assertions allow custom business logic in authorization decisions:

```go
type TimeWindowAssertion struct {
    Start, End int // Hours of day
}

func (a *TimeWindowAssertion) Assert(ctx context.Context, role rbac.Role, permission string) (bool, error) {
    hour := time.Now().Hour()
    return hour >= a.Start && hour <= a.End, nil
}

// Use in authorization
target := &rbac.Target{
    Action:     "sensitive.operation",
    Assertions: []rbac.Assertion{&TimeWindowAssertion{9, 17}},
}
```

### Context Integration

Built-in context functions for request-scoped data:

```go
// Add claims to context
ctx := rbac.WithClaims(context.Background(), claims)

// Add target and assertions
ctx = rbac.WithTarget(ctx, target)
ctx = rbac.WithAssertions(ctx, assertion1, assertion2)

// Extract from context
claims := rbac.CtxClaims(ctx)
target := rbac.CtxTarget(ctx)
assertions := rbac.CtxAssertions(ctx)
```

## API Reference

### Core Types

- **Role**: Interface for role entities with permissions and hierarchy
- **Subject**: Interface for entities that can be authorized
- **Authorizer**: Interface for high-level authorization decisions
- **Assertion**: Interface for custom authorization logic
- **Claims**: Wraps subject with metadata
- **Target**: Represents authorization requests
- **Decision**: Authorization decision (allow/deny)

### Main Functions

- `New() *RBAC`: Create new RBAC instance
- `NewWithConfig(config Config) (*RBAC, error)`: Create RBAC with configuration
- `NewRole(name string) Role`: Create new role
- `NewDefaultAuthorizer(rbac *RBAC) Authorizer`: Create default authorizer
- `RequestAuthorizer(authorizer Authorizer, actions func(*http.Request) []string) func(*http.Request) error`: Create HTTP middleware

### Context Functions

- `WithClaims(ctx context.Context, claims *Claims) context.Context`: Add claims to context
- `CtxClaims(ctx context.Context) *Claims`: Extract claims from context
- `WithTarget(ctx context.Context, target *Target) context.Context`: Add target to context
- `WithAssertions(ctx context.Context, assertions ...Assertion) context.Context`: Add assertions to context

## Configuration

The RBAC library supports JSON/YAML configuration for declarative setup:

```json
{
  "createMissingRoles": true,
  "roleHierarchy": [
    {
      "role": "super_admin",
      "parents": []
    },
    {
      "role": "admin",
      "parents": ["super_admin"],
      "children": ["user"]
    },
    {
      "role": "user",
      "parents": ["admin"]
    }
  ],
  "accessControl": [
    {
      "role": "super_admin",
      "permissions": ["*"]
    },
    {
      "role": "admin",
      "permissions": ["user.*", "post.*", "system.view"]
    },
    {
      "role": "user",
      "permissions": ["post.view", "post.create", "comment.*"]
    }
  ]
}
```

## License

Distributed under MIT License, please see license file within the code for more details.
