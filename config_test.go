package rbac

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type configSuit struct {
	suite.Suite
	rbac *RBAC
}

func TestConfigSuite(t *testing.T) {
	s := new(configSuit)
	suite.Run(t, s)
}

func (s *configSuit) SetupTest() {
	s.rbac = New()
}

func (s *configSuit) TestNewWithConfig() {
	cfg := Config{
		CreateMissingRoles: true,
		RoleHierarchy: []RoleConfig{
			{
				Role: "admin",
				Children: []string{
					"user",
				},
			},
			{
				Role: "user",
			},
		},
		AccessControl: []AccessConfig{
			{
				Role: "admin",
				Permissions: []string{
					"read",
					"write",
					"delete",
				},
			},
			{
				Role: "user",
				Permissions: []string{
					"read",
				},
			},
		},
	}

	rbac, err := NewWithConfig(cfg)
	s.NoError(err)
	s.NotNil(rbac)

	// Verify admin role has all permissions
	admin, err := rbac.Role("admin")
	s.NoError(err)
	s.True(admin.HasPermission("read"))
	s.True(admin.HasPermission("write"))
	s.True(admin.HasPermission("delete"))

	// Verify user role has read permission
	user, err := rbac.Role("user")
	s.NoError(err)
	s.True(user.HasPermission("read"))
	s.False(user.HasPermission("write"))
}

func (s *configSuit) TestNewWithConfigEmpty() {
	cfg := Config{}

	rbac, err := NewWithConfig(cfg)
	s.NoError(err)
	s.NotNil(rbac)
	s.False(rbac.createMissingRoles) // Default value should be false
}

func (s *configSuit) TestApply() {
	cfg := Config{
		CreateMissingRoles: true,
		RoleHierarchy: []RoleConfig{
			{
				Role: "root",
			},
			{
				Role: "admin",
				Parents: []string{
					"root",
				},
			},
		},
		AccessControl: []AccessConfig{
			{
				Role: "root",
				Permissions: []string{
					"sudo",
				},
			},
			{
				Role: "admin",
				Permissions: []string{
					"manage_users",
				},
			},
		},
	}

	err := s.rbac.Apply(cfg)
	s.NoError(err)

	// Verify roles exist
	root, err := s.rbac.Role("root")
	s.NoError(err)
	s.NotNil(root)

	admin, err := s.rbac.Role("admin")
	s.NoError(err)
	s.NotNil(admin)

	// Verify role hierarchy
	s.Contains(admin.Parents(), root)
	s.Contains(root.Children(), admin)

	// Verify permissions
	s.True(root.HasPermission("sudo"))
	s.True(admin.HasPermission("manage_users"))
}

func (s *configSuit) TestApplyRoleHierarchy() {
	cfg := Config{
		CreateMissingRoles: true,
		RoleHierarchy: []RoleConfig{
			{
				Role: "manager",
				Children: []string{
					"employee",
					"intern",
				},
			},
			{
				Role: "employee",
				Parents: []string{
					"manager",
				},
			},
			{
				Role: "intern",
				Parents: []string{
					"manager",
				},
			},
		},
	}

	err := s.rbac.Apply(cfg)
	s.NoError(err)

	manager, err := s.rbac.Role("manager")
	s.NoError(err)

	employee, err := s.rbac.Role("employee")
	s.NoError(err)

	intern, err := s.rbac.Role("intern")
	s.NoError(err)

	// Verify parent-child relationships
	s.Contains(employee.Parents(), manager)
	s.Contains(intern.Parents(), manager)
	s.Contains(manager.Children(), employee)
	s.Contains(manager.Children(), intern)
}

func (s *configSuit) TestApplyAccessControl() {
	cfg := Config{
		RoleHierarchy: []RoleConfig{
			{
				Role: "developer",
			},
			{
				Role: "tester",
			},
			{
				Role: "devops",
			},
		},
		AccessControl: []AccessConfig{
			{
				Role: "developer",
				Permissions: []string{
					"code:read",
					"code:write",
					"build:run",
				},
			},
			{
				Role: "tester",
				Permissions: []string{
					"test:read",
					"test:write",
					"test:execute",
				},
			},
			{
				Role: "devops",
				Permissions: []string{
					"deploy:staging",
					"deploy:production",
					"monitor:read",
				},
			},
		},
	}

	err := s.rbac.Apply(cfg)
	s.NoError(err)

	// Test developer permissions
	developer, err := s.rbac.Role("developer")
	s.NoError(err)
	s.True(developer.HasPermission("code:read"))
	s.True(developer.HasPermission("code:write"))
	s.True(developer.HasPermission("build:run"))
	s.False(developer.HasPermission("test:execute"))

	// Test tester permissions
	tester, err := s.rbac.Role("tester")
	s.NoError(err)
	s.True(tester.HasPermission("test:read"))
	s.True(tester.HasPermission("test:write"))
	s.True(tester.HasPermission("test:execute"))
	s.False(tester.HasPermission("code:write"))

	// Test devops permissions
	devops, err := s.rbac.Role("devops")
	s.NoError(err)
	s.True(devops.HasPermission("deploy:staging"))
	s.True(devops.HasPermission("deploy:production"))
	s.True(devops.HasPermission("monitor:read"))
	s.False(devops.HasPermission("code:read"))
}

func (s *configSuit) TestApplyEmptyPermissions() {
	cfg := Config{
		RoleHierarchy: []RoleConfig{
			{
				Role: "guest",
			},
		},
		AccessControl: []AccessConfig{
			{
				Role:        "guest",
				Permissions: []string{}, // Empty permissions should be skipped
			},
		},
	}

	err := s.rbac.Apply(cfg)
	s.NoError(err)

	guest, err := s.rbac.Role("guest")
	s.NoError(err)

	// Guest should have no permissions
	s.False(guest.HasPermission("read"))
	s.False(guest.HasPermission("write"))
}

func (s *configSuit) TestApplyCreateMissingRolesEnabled() {
	cfg := Config{
		CreateMissingRoles: true,
		RoleHierarchy: []RoleConfig{
			{
				Role: "super_admin",
			},
			{
				Role: "admin",
			},
		},
		AccessControl: []AccessConfig{
			{
				Role: "admin", // This role will be auto-created
				Permissions: []string{
					"admin_panel",
				},
			},
		},
	}

	err := s.rbac.Apply(cfg)
	s.NoError(err)

	// Both roles should exist now
	superAdmin, err := s.rbac.Role("super_admin")
	s.NoError(err)
	s.NotNil(superAdmin)

	admin, err := s.rbac.Role("admin")
	s.NoError(err)
	s.NotNil(admin)
	s.True(admin.HasPermission("admin_panel"))
}

func (s *configSuit) TestApplyCreateMissingRolesDisabled() {
	cfg := Config{
		CreateMissingRoles: false,
		AccessControl: []AccessConfig{
			{
				Role: "nonexistent_role",
				Permissions: []string{
					"some_permission",
				},
			},
		},
	}

	err := s.rbac.Apply(cfg)
	s.Error(err)
	s.Contains(err.Error(), "role not found")
}

func (s *configSuit) TestApplyComplexHierarchy() {
	cfg := Config{
		RoleHierarchy: []RoleConfig{
			{
				Role: "ceo",
				Children: []string{
					"cto",
					"cfo",
				},
			},
			{
				Role: "cto",
				Parents: []string{
					"ceo",
				},
				Children: []string{
					"engineer",
					"architect",
				},
			},
			{
				Role: "cfo",
				Parents: []string{
					"ceo",
				},
				Children: []string{
					"accountant",
				},
			},
			{
				Role: "engineer",
				Parents: []string{
					"cto",
				},
			},
			{
				Role: "architect",
				Parents: []string{
					"cto",
				},
			},
			{
				Role: "accountant",
				Parents: []string{
					"cfo",
				},
			},
		},
	}

	err := s.rbac.Apply(cfg)
	s.NoError(err)

	// Verify all roles exist
	roles := []string{"ceo", "cto", "cfo", "engineer", "architect", "accountant"}
	for _, roleName := range roles {
		role, err := s.rbac.Role(roleName)
		s.NoError(err)
		s.NotNil(role)
	}

	// Verify specific relationships
	ceo, _ := s.rbac.Role("ceo")
	cto, _ := s.rbac.Role("cto")
	engineer, _ := s.rbac.Role("engineer")

	s.Contains(cto.Parents(), ceo)
	s.Contains(ceo.Children(), cto)
	s.Contains(engineer.Parents(), cto)
	s.Contains(cto.Children(), engineer)
}

func (s *configSuit) TestApplyMultipleTimes() {
	cfg1 := Config{
		RoleHierarchy: []RoleConfig{
			{
				Role: "role1",
			},
		},
		AccessControl: []AccessConfig{
			{
				Role: "role1",
				Permissions: []string{
					"permission1",
				},
			},
		},
	}

	cfg2 := Config{
		RoleHierarchy: []RoleConfig{
			{
				Role: "role2",
			},
		},
		AccessControl: []AccessConfig{
			{
				Role: "role2",
				Permissions: []string{
					"permission2",
				},
			},
		},
	}

	// Apply first config
	err := s.rbac.Apply(cfg1)
	s.NoError(err)

	// Apply second config
	err = s.rbac.Apply(cfg2)
	s.NoError(err)

	// Both roles should exist with their permissions
	role1, err := s.rbac.Role("role1")
	s.NoError(err)
	s.True(role1.HasPermission("permission1"))

	role2, err := s.rbac.Role("role2")
	s.NoError(err)
	s.True(role2.HasPermission("permission2"))
}
