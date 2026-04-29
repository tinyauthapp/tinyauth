package decoders_test

import (
	"testing"

	"github.com/tinyauthapp/tinyauth/internal/config"
	"github.com/tinyauthapp/tinyauth/internal/utils/decoders"

	"gotest.tools/v3/assert"
)

func TestDecodeLabels(t *testing.T) {
	// Variables
	expected := config.Apps{
		Apps: map[string]config.App{
			"foo": {
				Config: config.AppConfig{
					Domain: "example.com",
				},
				Users: config.AppUsers{
					Allow: "user1,user2",
					Block: "user3",
				},
				OAuth: config.AppOAuth{
					Whitelist: "somebody@example.com",
					Groups:    "group3",
				},
				IP: config.AppIP{
					Allow:  []string{"10.71.0.1/24", "10.71.0.2"},
					Block:  []string{"10.10.10.10", "10.0.0.0/24"},
					Bypass: []string{"192.168.1.1"},
				},
				Response: config.AppResponse{
					Headers: []string{"X-Foo=Bar", "X-Baz=Qux"},
					BasicAuth: config.AppBasicAuth{
						Username:     "admin",
						Password:     "password",
						PasswordFile: "/path/to/passwordfile",
					},
				},
				Path: config.AppPath{
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
	result, err := decoders.DecodeLabels[config.Apps](test, "apps")
	assert.NilError(t, err)
	assert.DeepEqual(t, expected, result)
}
