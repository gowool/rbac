# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go-based Role-Based Access Control (RBAC) library that provides hierarchical role management and permission checking with support for regex patterns and assertions. The library implements a flexible authorization system suitable for Go applications.

## Development Commands

### Testing
```bash
# Clear test cache
go clean -testcache

# Run all tests
go test -race ./...

# Run tests with verbose output
go test -race -v ./...

# Run specific test
go test -race -run TestIsGrantedAssertion

# Run tests with coverage
go test -race -cover ./...
```

### Building
```bash
# Build the package
go build ./...

# Build with verbose output
go build -v ./...
```

### Code Quality
```bash
# Format code
go fmt ./...

# Run go vet
go vet ./...

# Run go mod tidy to clean dependencies
go mod tidy
```

## Architecture

### Core Components

1. **RBAC (`rbac.go`)** - Main orchestrator that manages roles and provides authorization checking
   - `IsGranted/IsGrantedE` methods check if a role has a specific permission
   - Supports role hierarchy with automatic parent-child relationship management
   - Can auto-create missing roles when `CreateMissingRoles` is enabled

2. **Role (`role.go`)** - Represents a role with permissions and hierarchical relationships
   - Supports both string permissions and regex patterns
   - Maintains parent-child relationships with circular reference detection
   - `HasPermission` checks include inherited permissions from child roles

3. **Authorizer (`authorizer.go`)** - Higher-level authorization interface for subject-based access control
   - Works with `Subject` interface (has identifier and roles)
   - Supports both permission checks and custom assertions
   - Returns `DecisionAllow` or `DecisionDeny` with error details

4. **Context (`context.go`, `authorizer_request.go`)** - Request context and authorization request structures

### Key Design Patterns

- **Interface-based design**: Core components use interfaces (`Role`, `Authorizer`, `Assertion`) for flexibility
- **Hierarchical permissions**: Child roles inherit permissions from parent roles
- **Regex pattern support**: Permissions can be exact strings or regex patterns
- **Assertion system**: Custom business logic can be added to authorization decisions
- **Circular reference protection**: Prevents infinite loops in role hierarchies

## Testing

- Uses testify/suite for structured test organization
- Tests cover role hierarchies, permission inheritance, assertions, and edge cases
- Located in `*_test.go` files alongside source files

## Dependencies

- `github.com/stretchr/testify` for testing
- Standard library only for core functionality
- Go 1.25+ required