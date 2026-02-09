package rbac

type RoleConfig struct {
	Role     string   `env:"ROLE" json:"role,omitempty" yaml:"role,omitempty"`
	Parents  []string `env:"PARENTS" json:"parents,omitempty" yaml:"parents,omitempty"`
	Children []string `env:"CHILDREN" json:"children,omitempty" yaml:"children,omitempty"`
}

type AccessConfig struct {
	Role        string   `env:"ROLE" json:"role,omitempty" yaml:"role,omitempty"`
	Permissions []string `env:"PERMISSIONS" json:"permissions,omitempty" yaml:"permissions,omitempty"`
}

type Config struct {
	CreateMissingRoles bool           `env:"CREATE_MISSING_ROLES" json:"createMissingRoles,omitempty" yaml:"createMissingRoles,omitempty"`
	RoleHierarchy      []RoleConfig   `envPrefix:"ROLE_CONFIG_" json:"roleHierarchy,omitempty" yaml:"roleHierarchy,omitempty"`
	AccessControl      []AccessConfig `envPrefix:"ACCESS_CONFIG_" json:"accessControl,omitempty" yaml:"accessControl,omitempty"`
}

func NewWithConfig(cfg Config) (*RBAC, error) {
	rbac := New()
	err := rbac.Apply(cfg)
	return rbac, err
}

func (rbac *RBAC) Apply(cfg Config) error {
	rbac.SetCreateMissingRoles(cfg.CreateMissingRoles)

	for _, role := range cfg.RoleHierarchy {
		if err := rbac.AddRole(role.Role); err != nil {
			return err
		}
	}

	for _, role := range cfg.RoleHierarchy {
		r, err := rbac.Role(role.Role)
		if err != nil {
			return err
		}

		for _, parent := range role.Parents {
			p, err := rbac.Role(parent)
			if err != nil {
				return err
			}
			if err = r.AddParent(p); err != nil {
				return err
			}
		}

		for _, child := range role.Children {
			c, err := rbac.Role(child)
			if err != nil {
				return err
			}
			if err = r.AddChild(c); err != nil {
				return err
			}
		}
	}

	for _, access := range cfg.AccessControl {
		r, err := rbac.Role(access.Role)
		if err != nil {
			return err
		}
		r.AddPermissions(access.Permissions...)
	}
	return nil
}
