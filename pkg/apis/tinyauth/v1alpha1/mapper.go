package v1alpha1

import (
	"github.com/tinyauthapp/tinyauth/internal/model"
)

// ToInternalApp converts the ApplicationSpec to the internal App structure
func (s *ApplicationSpec) ToInternalApp() model.App {
	return model.App{
		Config: model.AppConfig{
			Domain: s.Config.Domain,
		},
		Users: model.AppUsers{
			Allow: s.Users.Allow,
			Block: s.Users.Block,
		},
		OAuth: model.AppOAuth{
			Whitelist: s.OAuth.Whitelist,
			Groups:    s.OAuth.Groups,
		},
		IP: model.AppIP{
			Allow:  s.IP.Allow,
			Block:  s.IP.Block,
			Bypass: s.IP.Bypass,
		},
		Response: model.AppResponse{
			Headers: s.Response.Headers,
			BasicAuth: model.AppBasicAuth{
				Username:     s.Response.BasicAuth.Username,
				Password:     s.Response.BasicAuth.Password,
				PasswordFile: s.Response.BasicAuth.PasswordFile,
			},
		},
		Path: model.AppPath{
			Allow: s.Path.Allow,
			Block: s.Path.Block,
		},
		LDAP: model.AppLDAP{
			Groups: s.LDAP.Groups,
		},
	}
}
