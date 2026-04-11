package service_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/steveiliop56/tinyauth/internal/config"
	"github.com/steveiliop56/tinyauth/internal/repository"
	"github.com/steveiliop56/tinyauth/internal/service"
)

func newTestUser() repository.OidcUserinfo {
	addr := config.AddressClaim{
		Formatted:     "123 Main St",
		StreetAddress: "123 Main St",
		Locality:      "Springfield",
		Region:        "IL",
		PostalCode:    "62701",
		Country:       "US",
	}
	addrJSON, _ := json.Marshal(addr)

	return repository.OidcUserinfo{
		Sub:               "test-sub",
		Name:              "Test User",
		PreferredUsername: "testuser",
		Email:             "test@example.com",
		Groups:            "admins,users",
		UpdatedAt:         1234567890,
		GivenName:         "Test",
		FamilyName:        "User",
		MiddleName:        "M",
		Nickname:          "testy",
		Profile:           "https://example.com/testuser",
		Picture:           "https://example.com/testuser.jpg",
		Website:           "https://testuser.example.com",
		Gender:            "male",
		Birthdate:         "1990-01-01",
		Zoneinfo:          "America/Chicago",
		Locale:            "en-US",
		PhoneNumber:       "+15555550100",
		Address:           string(addrJSON),
	}
}

func TestCompileUserinfo(t *testing.T) {
	dir := t.TempDir()
	svc := service.NewOIDCService(service.OIDCServiceConfig{
		PrivateKeyPath: dir + "/key.pem",
		PublicKeyPath:  dir + "/key.pub",
		Issuer:         "https://tinyauth.example.com",
		SessionExpiry:  3600,
	}, nil)
	require.NoError(t, svc.Init())

	type testCase struct {
		description string
		mutate      func(u *repository.OidcUserinfo)
		scope       string
		run         func(t *testing.T, info service.UserinfoResponse)
	}

	tests := []testCase{
		{
			description: "openid scope only returns sub and updated_at",
			scope:       "openid",
			run: func(t *testing.T, info service.UserinfoResponse) {
				assert.Equal(t, "test-sub", info.Sub)
				assert.Equal(t, int64(1234567890), info.UpdatedAt)
				assert.Empty(t, info.Name)
				assert.Empty(t, info.Email)
				assert.Nil(t, info.Groups)
				assert.Nil(t, info.PhoneNumberVerified)
				assert.Nil(t, info.Address)
			},
		},
		{
			description: "profile scope returns all profile fields",
			scope:       "openid,profile",
			run: func(t *testing.T, info service.UserinfoResponse) {
				assert.Equal(t, "Test User", info.Name)
				assert.Equal(t, "testuser", info.PreferredUsername)
				assert.Equal(t, "Test", info.GivenName)
				assert.Equal(t, "User", info.FamilyName)
				assert.Equal(t, "M", info.MiddleName)
				assert.Equal(t, "testy", info.Nickname)
				assert.Equal(t, "https://example.com/testuser", info.Profile)
				assert.Equal(t, "https://example.com/testuser.jpg", info.Picture)
				assert.Equal(t, "https://testuser.example.com", info.Website)
				assert.Equal(t, "male", info.Gender)
				assert.Equal(t, "1990-01-01", info.Birthdate)
				assert.Equal(t, "America/Chicago", info.Zoneinfo)
				assert.Equal(t, "en-US", info.Locale)
				assert.Empty(t, info.Email)
			},
		},
		{
			description: "email scope sets email and email_verified true when email present",
			scope:       "openid,email",
			run: func(t *testing.T, info service.UserinfoResponse) {
				assert.Equal(t, "test@example.com", info.Email)
				assert.True(t, info.EmailVerified)
				assert.Empty(t, info.Name)
			},
		},
		{
			description: "email scope sets email_verified false when email absent",
			scope:       "openid,email",
			mutate:      func(u *repository.OidcUserinfo) { u.Email = "" },
			run: func(t *testing.T, info service.UserinfoResponse) {
				assert.Empty(t, info.Email)
				assert.False(t, info.EmailVerified)
			},
		},
		{
			description: "phone scope sets phone_number_verified true when phone present",
			scope:       "openid,phone",
			run: func(t *testing.T, info service.UserinfoResponse) {
				assert.Equal(t, "+15555550100", info.PhoneNumber)
				require.NotNil(t, info.PhoneNumberVerified)
				assert.True(t, *info.PhoneNumberVerified)
			},
		},
		{
			description: "phone scope sets phone_number_verified false when phone absent",
			scope:       "openid,phone",
			mutate:      func(u *repository.OidcUserinfo) { u.PhoneNumber = "" },
			run: func(t *testing.T, info service.UserinfoResponse) {
				require.NotNil(t, info.PhoneNumberVerified)
				assert.False(t, *info.PhoneNumberVerified)
			},
		},
		{
			description: "address scope returns parsed address",
			scope:       "openid,address",
			run: func(t *testing.T, info service.UserinfoResponse) {
				require.NotNil(t, info.Address)
				assert.Equal(t, "123 Main St", info.Address.Formatted)
				assert.Equal(t, "123 Main St", info.Address.StreetAddress)
				assert.Equal(t, "Springfield", info.Address.Locality)
				assert.Equal(t, "IL", info.Address.Region)
				assert.Equal(t, "62701", info.Address.PostalCode)
				assert.Equal(t, "US", info.Address.Country)
			},
		},
		{
			description: "address scope with invalid JSON omits address",
			scope:       "openid,address",
			mutate:      func(u *repository.OidcUserinfo) { u.Address = "not-valid-json" },
			run: func(t *testing.T, info service.UserinfoResponse) {
				assert.Nil(t, info.Address)
			},
		},
		{
			description: "groups scope returns split groups",
			scope:       "openid,groups",
			run: func(t *testing.T, info service.UserinfoResponse) {
				assert.Equal(t, []string{"admins", "users"}, info.Groups)
			},
		},
		{
			description: "groups scope returns empty slice when no groups",
			scope:       "openid,groups",
			mutate:      func(u *repository.OidcUserinfo) { u.Groups = "" },
			run: func(t *testing.T, info service.UserinfoResponse) {
				assert.Equal(t, []string{}, info.Groups)
			},
		},
		{
			description: "all scopes return all fields",
			scope:       "openid,profile,email,phone,address,groups",
			run: func(t *testing.T, info service.UserinfoResponse) {
				assert.Equal(t, "Test User", info.Name)
				assert.Equal(t, "test@example.com", info.Email)
				assert.Equal(t, "+15555550100", info.PhoneNumber)
				require.NotNil(t, info.PhoneNumberVerified)
				assert.True(t, *info.PhoneNumberVerified)
				require.NotNil(t, info.Address)
				assert.Equal(t, "Springfield", info.Address.Locality)
				assert.Equal(t, []string{"admins", "users"}, info.Groups)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			user := newTestUser()
			if test.mutate != nil {
				test.mutate(&user)
			}
			info := svc.CompileUserinfo(user, test.scope)
			test.run(t, info)
		})
	}
}
