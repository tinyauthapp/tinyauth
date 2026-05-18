package service

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

func TestUserAllowedRule(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	rule := &UserAllowedRule{Log: log}

	tests := []struct {
		name     string
		ctx      *ACLContext
		expected Effect
	}{
		{
			name: "abstains when ACLs are nil",
			ctx: &ACLContext{
				ACLs: nil,
				UserContext: &model.UserContext{
					Provider: model.ProviderLocal,
					Local: &model.LocalContext{
						BaseContext: model.BaseContext{Username: "alice"},
					},
				},
			},
			expected: EffectAbstain,
		},
		{
			name: "abstains when user context is nil",
			ctx: &ACLContext{
				ACLs: &model.App{
					OAuth: model.AppOAuth{Whitelist: "alice"},
				},
				UserContext: nil,
			},
			expected: EffectAbstain,
		},
		{
			name: "allows OAuth user when email matches whitelist",
			ctx: &ACLContext{
				ACLs: &model.App{
					OAuth: model.AppOAuth{Whitelist: "allowed@example.com"},
				},
				UserContext: &model.UserContext{
					Provider: model.ProviderOAuth,
					OAuth: &model.OAuthContext{
						BaseContext: model.BaseContext{
							Username: "different-username",
							Email:    "allowed@example.com",
						},
					},
				},
			},
			expected: EffectAllow,
		},
		{
			name: "denies OAuth user when email does not match whitelist",
			ctx: &ACLContext{
				ACLs: &model.App{
					OAuth: model.AppOAuth{Whitelist: "allowed@example.com"},
				},
				UserContext: &model.UserContext{
					Provider: model.ProviderOAuth,
					OAuth: &model.OAuthContext{
						BaseContext: model.BaseContext{Email: "denied@example.com"},
					},
				},
			},
			expected: EffectDeny,
		},
		{
			name: "abstains for OAuth user when whitelist filter is invalid",
			ctx: &ACLContext{
				ACLs: &model.App{
					OAuth: model.AppOAuth{Whitelist: "/[/"},
				},
				UserContext: &model.UserContext{
					Provider: model.ProviderOAuth,
					OAuth: &model.OAuthContext{
						BaseContext: model.BaseContext{Email: "allowed@example.com"},
					},
				},
			},
			expected: EffectAbstain,
		},
		{
			name: "denies local user when username matches block list",
			ctx: &ACLContext{
				ACLs: &model.App{
					Users: model.AppUsers{Block: "alice,bob"},
				},
				UserContext: &model.UserContext{
					Provider: model.ProviderLocal,
					Local: &model.LocalContext{
						BaseContext: model.BaseContext{Username: "alice"},
					},
				},
			},
			expected: EffectDeny,
		},
		{
			name: "allows local user when username does not match block list",
			ctx: &ACLContext{
				ACLs: &model.App{
					Users: model.AppUsers{Block: "alice,bob"},
				},
				UserContext: &model.UserContext{
					Provider: model.ProviderLocal,
					Local: &model.LocalContext{
						BaseContext: model.BaseContext{Username: "charlie"},
					},
				},
			},
			expected: EffectAllow,
		},
		{
			name: "abstains when block list filter is invalid",
			ctx: &ACLContext{
				ACLs: &model.App{
					Users: model.AppUsers{Block: "/[/"},
				},
				UserContext: &model.UserContext{
					Provider: model.ProviderLocal,
					Local: &model.LocalContext{
						BaseContext: model.BaseContext{Username: "alice"},
					},
				},
			},
			expected: EffectAbstain,
		},
		{
			name: "allows local user when username matches allow list",
			ctx: &ACLContext{
				ACLs: &model.App{
					Users: model.AppUsers{Allow: "alice,bob"},
				},
				UserContext: &model.UserContext{
					Provider: model.ProviderLocal,
					Local: &model.LocalContext{
						BaseContext: model.BaseContext{Username: "alice"},
					},
				},
			},
			expected: EffectAllow,
		},
		{
			name: "denies local user when username does not match allow list",
			ctx: &ACLContext{
				ACLs: &model.App{
					Users: model.AppUsers{Allow: "alice,bob"},
				},
				UserContext: &model.UserContext{
					Provider: model.ProviderLocal,
					Local: &model.LocalContext{
						BaseContext: model.BaseContext{Username: "charlie"},
					},
				},
			},
			expected: EffectDeny,
		},
		{
			name: "abstains when allow list filter is invalid",
			ctx: &ACLContext{
				ACLs: &model.App{
					Users: model.AppUsers{Allow: "/[/"},
				},
				UserContext: &model.UserContext{
					Provider: model.ProviderLocal,
					Local: &model.LocalContext{
						BaseContext: model.BaseContext{Username: "alice"},
					},
				},
			},
			expected: EffectAbstain,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, rule.Evaluate(tt.ctx))
		})
	}
}

func TestOAuthGroupRule(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	rule := &OAuthGroupRule{Log: log}

	tests := []struct {
		name     string
		ctx      *ACLContext
		expected Effect
	}{
		{
			name: "abstains when ACLs are nil",
			ctx: &ACLContext{
				ACLs: nil,
				UserContext: &model.UserContext{
					Provider: model.ProviderOAuth,
					OAuth: &model.OAuthContext{
						Groups: []string{"admins"},
					},
				},
			},
			expected: EffectAbstain,
		},
		{
			name: "abstains when user context is nil",
			ctx: &ACLContext{
				ACLs: &model.App{
					OAuth: model.AppOAuth{Whitelist: "alice"},
				},
				UserContext: nil,
			},
			expected: EffectAbstain,
		},
		{
			name: "abstains when user is not OAuth",
			ctx: &ACLContext{
				ACLs: &model.App{
					OAuth: model.AppOAuth{Groups: "admins"},
				},
				UserContext: &model.UserContext{
					Provider: model.ProviderLocal,
					Local: &model.LocalContext{
						BaseContext: model.BaseContext{Username: "alice"},
					},
				},
			},
			expected: EffectAbstain,
		},
		{
			name: "allows when provider is an override provider regardless of groups",
			ctx: &ACLContext{
				ACLs: &model.App{
					OAuth: model.AppOAuth{Groups: "admins"},
				},
				UserContext: &model.UserContext{
					Provider: model.ProviderOAuth,
					OAuth: &model.OAuthContext{
						ID:     "google",
						Groups: []string{"unrelated"},
					},
				},
			},
			expected: EffectAllow,
		},
		{
			name: "allows OAuth user when a group matches",
			ctx: &ACLContext{
				ACLs: &model.App{
					OAuth: model.AppOAuth{Groups: "admins,users"},
				},
				UserContext: &model.UserContext{
					Provider: model.ProviderOAuth,
					OAuth: &model.OAuthContext{
						ID:     "custom",
						Groups: []string{"users"},
					},
				},
			},
			expected: EffectAllow,
		},
		{
			name: "denies OAuth user when no group matches",
			ctx: &ACLContext{
				ACLs: &model.App{
					OAuth: model.AppOAuth{Groups: "admins"},
				},
				UserContext: &model.UserContext{
					Provider: model.ProviderOAuth,
					OAuth: &model.OAuthContext{
						ID:     "custom",
						Groups: []string{"users", "guests"},
					},
				},
			},
			expected: EffectDeny,
		},
		{
			name: "denies OAuth user when user has no groups",
			ctx: &ACLContext{
				ACLs: &model.App{
					OAuth: model.AppOAuth{Groups: "admins"},
				},
				UserContext: &model.UserContext{
					Provider: model.ProviderOAuth,
					OAuth: &model.OAuthContext{
						ID:     "custom",
						Groups: nil,
					},
				},
			},
			expected: EffectDeny,
		},
		{
			name: "abstains when groups filter is invalid",
			ctx: &ACLContext{
				ACLs: &model.App{
					OAuth: model.AppOAuth{Groups: "/[/"},
				},
				UserContext: &model.UserContext{
					Provider: model.ProviderOAuth,
					OAuth: &model.OAuthContext{
						ID:     "custom",
						Groups: []string{"admins"},
					},
				},
			},
			expected: EffectAbstain,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, rule.Evaluate(tt.ctx))
		})
	}
}

func TestLDAPGroupRule(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	rule := &LDAPGroupRule{Log: log}

	tests := []struct {
		name     string
		ctx      *ACLContext
		expected Effect
	}{
		{
			name:     "abstains when context is nil",
			ctx:      nil,
			expected: EffectAbstain,
		},
		{
			name: "abstains when user context is nil",
			ctx: &ACLContext{
				ACLs: &model.App{
					OAuth: model.AppOAuth{Whitelist: "alice"},
				},
				UserContext: nil,
			},
			expected: EffectAbstain,
		},
		{
			name: "abstains when user is not LDAP",
			ctx: &ACLContext{
				ACLs: &model.App{
					LDAP: model.AppLDAP{Groups: "admins"},
				},
				UserContext: &model.UserContext{
					Provider: model.ProviderLocal,
					Local: &model.LocalContext{
						BaseContext: model.BaseContext{Username: "alice"},
					},
				},
			},
			expected: EffectAbstain,
		},
		{
			name: "allows LDAP user when a group matches",
			ctx: &ACLContext{
				ACLs: &model.App{
					LDAP: model.AppLDAP{Groups: "admins,users"},
				},
				UserContext: &model.UserContext{
					Provider: model.ProviderLDAP,
					LDAP: &model.LDAPContext{
						Groups: []string{"users"},
					},
				},
			},
			expected: EffectAllow,
		},
		{
			name: "denies LDAP user when no group matches",
			ctx: &ACLContext{
				ACLs: &model.App{
					LDAP: model.AppLDAP{Groups: "admins"},
				},
				UserContext: &model.UserContext{
					Provider: model.ProviderLDAP,
					LDAP: &model.LDAPContext{
						Groups: []string{"users", "guests"},
					},
				},
			},
			expected: EffectDeny,
		},
		{
			name: "denies LDAP user when user has no groups",
			ctx: &ACLContext{
				ACLs: &model.App{
					LDAP: model.AppLDAP{Groups: "admins"},
				},
				UserContext: &model.UserContext{
					Provider: model.ProviderLDAP,
					LDAP: &model.LDAPContext{
						Groups: nil,
					},
				},
			},
			expected: EffectDeny,
		},
		{
			name: "abstains when groups filter is invalid",
			ctx: &ACLContext{
				ACLs: &model.App{
					LDAP: model.AppLDAP{Groups: "/[/"},
				},
				UserContext: &model.UserContext{
					Provider: model.ProviderLDAP,
					LDAP: &model.LDAPContext{
						Groups: []string{"admins"},
					},
				},
			},
			expected: EffectAbstain,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, rule.Evaluate(tt.ctx))
		})
	}
}

func TestAuthEnabledRule(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	rule := &AuthEnabledRule{Log: log}

	tests := []struct {
		name     string
		ctx      *ACLContext
		expected Effect
	}{
		{
			name: "deny when ACLs are nil",
			ctx: &ACLContext{
				ACLs: nil,
				Path: "/anything",
			},
			expected: EffectDeny,
		},
		{
			name: "allows when path does not match block regex",
			ctx: &ACLContext{
				ACLs: &model.App{
					Path: model.AppPath{Block: "^/admin"},
				},
				Path: "/public",
			},
			expected: EffectAllow,
		},
		{
			name: "denies when path matches block regex and no allow regex",
			ctx: &ACLContext{
				ACLs: &model.App{
					Path: model.AppPath{Block: "^/admin"},
				},
				Path: "/admin/users",
			},
			expected: EffectDeny,
		},
		{
			name: "allows when path matches allow regex",
			ctx: &ACLContext{
				ACLs: &model.App{
					Path: model.AppPath{Allow: "^/public"},
				},
				Path: "/public/index",
			},
			expected: EffectAllow,
		},
		{
			name: "denies when path does not match allow regex",
			ctx: &ACLContext{
				ACLs: &model.App{
					Path: model.AppPath{Allow: "^/public"},
				},
				Path: "/private",
			},
			expected: EffectDeny,
		},
		{
			name: "allows when blocked path is also explicitly allowed",
			ctx: &ACLContext{
				ACLs: &model.App{
					Path: model.AppPath{
						Block: "^/admin",
						Allow: "^/admin/public",
					},
				},
				Path: "/admin/public/page",
			},
			expected: EffectAllow,
		},
		{
			name: "denies when block regex fails to compile",
			ctx: &ACLContext{
				ACLs: &model.App{
					Path: model.AppPath{Block: "[invalid"},
				},
				Path: "/anything",
			},
			expected: EffectDeny,
		},
		{
			name: "denies when allow regex fails to compile",
			ctx: &ACLContext{
				ACLs: &model.App{
					Path: model.AppPath{Allow: "[invalid"},
				},
				Path: "/anything",
			},
			expected: EffectDeny,
		},
		{
			name: "denies when no path rules are configured",
			ctx: &ACLContext{
				ACLs: &model.App{},
				Path: "/anything",
			},
			expected: EffectDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, rule.Evaluate(tt.ctx))
		})
	}
}

func TestIPAllowedRule(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	tests := []struct {
		name     string
		config   model.Config
		ctx      *ACLContext
		expected Effect
	}{
		{
			name: "abstains when ACLs are nil",
			ctx: &ACLContext{
				ACLs: nil,
				IP:   net.ParseIP("10.0.0.1"),
			},
			expected: EffectAbstain,
		},
		{
			name: "denies when IP matches app block list",
			ctx: &ACLContext{
				ACLs: &model.App{
					IP: model.AppIP{Block: []string{"10.0.0.1"}},
				},
				IP: net.ParseIP("10.0.0.1"),
			},
			expected: EffectDeny,
		},
		{
			name: "denies when IP matches global block list",
			config: model.Config{
				Auth: model.AuthConfig{
					IP: model.IPConfig{Block: []string{"10.0.0.0/24"}},
				},
			},
			ctx: &ACLContext{
				ACLs: &model.App{},
				IP:   net.ParseIP("10.0.0.5"),
			},
			expected: EffectDeny,
		},
		{
			name: "allows when IP matches app allow list",
			ctx: &ACLContext{
				ACLs: &model.App{
					IP: model.AppIP{Allow: []string{"192.168.1.0/24"}},
				},
				IP: net.ParseIP("192.168.1.10"),
			},
			expected: EffectAllow,
		},
		{
			name: "allows when IP matches global allow list",
			config: model.Config{
				Auth: model.AuthConfig{
					IP: model.IPConfig{Allow: []string{"192.168.1.10"}},
				},
			},
			ctx: &ACLContext{
				ACLs: &model.App{},
				IP:   net.ParseIP("192.168.1.10"),
			},
			expected: EffectAllow,
		},
		{
			name: "denies when allow list is set and IP does not match",
			ctx: &ACLContext{
				ACLs: &model.App{
					IP: model.AppIP{Allow: []string{"192.168.1.0/24"}},
				},
				IP: net.ParseIP("10.0.0.1"),
			},
			expected: EffectDeny,
		},
		{
			name: "allows when no block or allow lists are configured",
			ctx: &ACLContext{
				ACLs: &model.App{},
				IP:   net.ParseIP("10.0.0.1"),
			},
			expected: EffectAllow,
		},
		{
			name: "block list takes precedence over allow list",
			ctx: &ACLContext{
				ACLs: &model.App{
					IP: model.AppIP{
						Block: []string{"10.0.0.1"},
						Allow: []string{"10.0.0.1"},
					},
				},
				IP: net.ParseIP("10.0.0.1"),
			},
			expected: EffectDeny,
		},
		{
			name: "skips invalid block entries and continues evaluation",
			ctx: &ACLContext{
				ACLs: &model.App{
					IP: model.AppIP{
						Block: []string{"not-an-ip"},
						Allow: []string{"10.0.0.1"},
					},
				},
				IP: net.ParseIP("10.0.0.1"),
			},
			expected: EffectAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &IPAllowedRule{Log: log, Config: tt.config}
			assert.Equal(t, tt.expected, rule.Evaluate(tt.ctx))
		})
	}
}

func TestIPBypassedRule(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	rule := &IPBypassedRule{Log: log}

	tests := []struct {
		name     string
		ctx      *ACLContext
		expected Effect
	}{
		{
			name: "deny when ACLs are nil",
			ctx: &ACLContext{
				ACLs: nil,
				IP:   net.ParseIP("10.0.0.1"),
			},
			expected: EffectDeny,
		},
		{
			name: "allows when IP matches bypass list",
			ctx: &ACLContext{
				ACLs: &model.App{
					IP: model.AppIP{Bypass: []string{"10.0.0.0/24"}},
				},
				IP: net.ParseIP("10.0.0.5"),
			},
			expected: EffectAllow,
		},
		{
			name: "denies when IP does not match bypass list",
			ctx: &ACLContext{
				ACLs: &model.App{
					IP: model.AppIP{Bypass: []string{"10.0.0.0/24"}},
				},
				IP: net.ParseIP("192.168.1.1"),
			},
			expected: EffectDeny,
		},
		{
			name: "denies when bypass list is empty",
			ctx: &ACLContext{
				ACLs: &model.App{},
				IP:   net.ParseIP("10.0.0.1"),
			},
			expected: EffectDeny,
		},
		{
			name: "skips invalid bypass entries and allows on later match",
			ctx: &ACLContext{
				ACLs: &model.App{
					IP: model.AppIP{Bypass: []string{"not-an-ip", "10.0.0.1"}},
				},
				IP: net.ParseIP("10.0.0.1"),
			},
			expected: EffectAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, rule.Evaluate(tt.ctx))
		})
	}
}
