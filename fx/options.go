package echox

import (
	"go.uber.org/fx"

	"github.com/gowool/rbac"
)

var (
	OptionRBAC                 = fx.Provide(rbac.New)
	OptionRBACWithConfig       = fx.Provide(rbac.NewWithConfig)
	OptionAuthorizationChecker = fx.Provide(func(rbac *rbac.RBAC) rbac.AuthorizationChecker { return rbac })
	OptionAuthorizer           = fx.Provide(fx.Annotate(rbac.NewDefaultAuthorizer, fx.As(new(rbac.Authorizer))))
)
