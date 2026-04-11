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
		Sub:                 "test-sub",
		Name:                "Test User",
		PreferredUsername:   "testuser",
		Email:               "test@example.com",
		Groups:              "admins,users",
		UpdatedAt:           1234567890,
		GivenName:           "Test",
		FamilyName:          "User",
		MiddleName:          "M",
		Nickname:            "testy",
		Profile:             "https://example.com/testuser",
		Picture:             "https://example.com/testuser.jpg",
		Website:             "https://testuser.example.com",
		Gender:              "male",
		Birthdate:           "1990-01-01",
		Zoneinfo:            "America/Chicago",
		Locale:              "en-US",
		PhoneNumber:         "+15555550100",
		PhoneNumberVerified: 1,
		Address:             string(addrJSON),
	}
}

func newOIDCService(t *testing.T) *service.OIDCService {
	t.Helper()
	dir := t.TempDir()
	svc := service.NewOIDCService(service.OIDCServiceConfig{
		PrivateKeyPath: dir + "/key.pem",
		PublicKeyPath:  dir + "/key.pub",
		Issuer:         "https://tinyauth.example.com",
		SessionExpiry:  3600,
	}, nil)
	require.NoError(t, svc.Init())
	return svc
}

func TestCompileUserinfo_OpenidOnly(t *testing.T) {
	svc := newOIDCService(t)
	user := newTestUser()

	info := svc.CompileUserinfo(user, "openid")

	assert.Equal(t, "test-sub", info.Sub)
	assert.Equal(t, int64(1234567890), info.UpdatedAt)
	// profile fields not requested
	assert.Empty(t, info.Name)
	assert.Empty(t, info.Email)
	assert.Nil(t, info.Groups)
	assert.Nil(t, info.PhoneNumberVerified)
	assert.Nil(t, info.Address)
}

func TestCompileUserinfo_ProfileScope(t *testing.T) {
	svc := newOIDCService(t)
	user := newTestUser()

	info := svc.CompileUserinfo(user, "openid,profile")

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
	// non-profile fields still absent
	assert.Empty(t, info.Email)
}

func TestCompileUserinfo_EmailScope(t *testing.T) {
	svc := newOIDCService(t)
	user := newTestUser()

	info := svc.CompileUserinfo(user, "openid,email")

	assert.Equal(t, "test@example.com", info.Email)
	assert.True(t, info.EmailVerified)
	assert.Empty(t, info.Name) // profile not requested
}

func TestCompileUserinfo_PhoneScope(t *testing.T) {
	svc := newOIDCService(t)
	user := newTestUser()

	info := svc.CompileUserinfo(user, "openid,phone")

	assert.Equal(t, "+15555550100", info.PhoneNumber)
	require.NotNil(t, info.PhoneNumberVerified)
	assert.True(t, *info.PhoneNumberVerified)
}

func TestCompileUserinfo_PhoneScope_Unverified(t *testing.T) {
	svc := newOIDCService(t)
	user := newTestUser()
	user.PhoneNumberVerified = 0

	info := svc.CompileUserinfo(user, "openid,phone")

	require.NotNil(t, info.PhoneNumberVerified)
	assert.False(t, *info.PhoneNumberVerified)
}

func TestCompileUserinfo_AddressScope(t *testing.T) {
	svc := newOIDCService(t)
	user := newTestUser()

	info := svc.CompileUserinfo(user, "openid,address")

	require.NotNil(t, info.Address)
	assert.Equal(t, "123 Main St", info.Address.Formatted)
	assert.Equal(t, "123 Main St", info.Address.StreetAddress)
	assert.Equal(t, "Springfield", info.Address.Locality)
	assert.Equal(t, "IL", info.Address.Region)
	assert.Equal(t, "62701", info.Address.PostalCode)
	assert.Equal(t, "US", info.Address.Country)
}

func TestCompileUserinfo_AddressScope_InvalidJSON(t *testing.T) {
	svc := newOIDCService(t)
	user := newTestUser()
	user.Address = "not-valid-json"

	info := svc.CompileUserinfo(user, "openid,address")

	// invalid JSON silently skipped, address omitted
	assert.Nil(t, info.Address)
}

func TestCompileUserinfo_GroupsScope(t *testing.T) {
	svc := newOIDCService(t)
	user := newTestUser()

	info := svc.CompileUserinfo(user, "openid,groups")

	assert.Equal(t, []string{"admins", "users"}, info.Groups)
}

func TestCompileUserinfo_GroupsScope_Empty(t *testing.T) {
	svc := newOIDCService(t)
	user := newTestUser()
	user.Groups = ""

	info := svc.CompileUserinfo(user, "openid,groups")

	assert.Equal(t, []string{}, info.Groups)
}

func TestCompileUserinfo_AllScopes(t *testing.T) {
	svc := newOIDCService(t)
	user := newTestUser()

	info := svc.CompileUserinfo(user, "openid,profile,email,phone,address,groups")

	assert.Equal(t, "Test User", info.Name)
	assert.Equal(t, "test@example.com", info.Email)
	assert.Equal(t, "+15555550100", info.PhoneNumber)
	require.NotNil(t, info.PhoneNumberVerified)
	assert.True(t, *info.PhoneNumberVerified)
	require.NotNil(t, info.Address)
	assert.Equal(t, "Springfield", info.Address.Locality)
	assert.Equal(t, []string{"admins", "users"}, info.Groups)
}
