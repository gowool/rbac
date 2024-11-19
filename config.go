package rbac

type RoleConfig struct {
	Role     string   `json:"role,omitempty" yaml:"role,omitempty"`
	Parents  []string `json:"parents,omitempty" yaml:"parents,omitempty"`
	Children []string `json:"children,omitempty" yaml:"children,omitempty"`
}

type AccessConfig struct {
	Role        string   `json:"role,omitempty" yaml:"role,omitempty"`
	Permissions []string `json:"permissions,omitempty" yaml:"permissions,omitempty"`
}

type Config struct {
	CreateMissingRoles bool           `json:"createMissingRoles,omitempty" yaml:"createMissingRoles,omitempty"`
	RoleHierarchy      []RoleConfig   `json:"roleHierarchy,omitempty" yaml:"roleHierarchy,omitempty"`
	AccessControl      []AccessConfig `json:"accessControl,omitempty" yaml:"accessControl,omitempty"`
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
		if len(access.Permissions) == 0 {
			continue
		}
		r.AddPermissions(access.Permissions[0], access.Permissions[1:]...)
	}
	return nil
}
