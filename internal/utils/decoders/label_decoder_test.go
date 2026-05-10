package decoders_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/decoders"
)

func TestDecodeLabels(t *testing.T) {
	// Variables
	expected := model.Apps{
		Apps: map[string]model.App{
			"foo": {
				Config: model.AppConfig{
					Domain: "example.com",
				},
				Users: model.AppUsers{
					Allow: "user1,user2",
					Block: "user3",
				},
				OAuth: model.AppOAuth{
					Whitelist: "somebody@example.com",
					Groups:    "group3",
				},
				IP: model.AppIP{
					Allow:  []string{"10.71.0.1/24", "10.71.0.2"},
					Block:  []string{"10.10.10.10", "10.0.0.0/24"},
					Bypass: []string{"192.168.1.1"},
				},
				Response: model.AppResponse{
					Headers: []string{"X-Foo=Bar", "X-Baz=Qux"},
					BasicAuth: model.AppBasicAuth{
						Username:     "admin",
						Password:     "password",
						PasswordFile: "/path/to/passwordfile",
					},
				},
				Path: model.AppPath{
					Allow: "/public",
					Block: "/private",
				},
			},
		},
	}
	test := map[string]string{
		"tinyauth.apps.foo.config.domain":                   "example.com",
		"tinyauth.apps.foo.users.allow":                     "user1,user2",
		"tinyauth.apps.foo.users.block":                     "user3",
		"tinyauth.apps.foo.oauth.whitelist":                 "somebody@example.com",
		"tinyauth.apps.foo.oauth.groups":                    "group3",
		"tinyauth.apps.foo.ip.allow":                        "10.71.0.1/24,10.71.0.2",
		"tinyauth.apps.foo.ip.block":                        "10.10.10.10,10.0.0.0/24",
		"tinyauth.apps.foo.ip.bypass":                       "192.168.1.1",
		"tinyauth.apps.foo.response.headers":                "X-Foo=Bar,X-Baz=Qux",
		"tinyauth.apps.foo.response.basicauth.username":     "admin",
		"tinyauth.apps.foo.response.basicauth.password":     "password",
		"tinyauth.apps.foo.response.basicauth.passwordfile": "/path/to/passwordfile",
		"tinyauth.apps.foo.path.allow":                      "/public",
		"tinyauth.apps.foo.path.block":                      "/private",
	}

	// Test
	result, err := decoders.DecodeLabels[model.Apps](test, "apps")
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
}
