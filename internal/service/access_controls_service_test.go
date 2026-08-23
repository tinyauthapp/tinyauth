package service

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/test"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

type mockProvider struct {
	acls        map[string]model.App
	shouldError bool
}

func newMockProvider(acls map[string]model.App, shouldError bool) *mockProvider {
	return &mockProvider{acls: acls, shouldError: shouldError}
}

func (m *mockProvider) Lookup(locator func(name string, app *model.App) bool) error {
	if m.shouldError {
		return errors.New("mock error")
	}
	for name, app := range m.acls {
		if ok := locator(name, &app); ok {
			return nil
		}
	}
	return nil
}

func TestAccessControlsService(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	_, runtime := test.CreateTestConfigs(t)

	tests := []struct {
		name      string
		domain    string
		acls      map[string]model.App
		want      *model.App
		errorFunc func(t *testing.T, e error)
	}{
		{
			name:   "returns ACLs for domain",
			domain: "app.example.com",
			acls: map[string]model.App{
				"foo": {Config: model.AppConfig{Domain: "app.example.com"}},
			},
			want: &model.App{Config: model.AppConfig{Domain: "app.example.com"}},
		},
		{
			name:   "returns ACLs for root domain",
			domain: "example.com",
			acls: map[string]model.App{
				"foo": {Config: model.AppConfig{Domain: "example.com"}},
			},
			want: &model.App{Config: model.AppConfig{Domain: "example.com"}},
		},
		{
			name:   "returns ACLs for domain with port",
			domain: "example.com:8080",
			acls: map[string]model.App{
				"foo": {Config: model.AppConfig{Domain: "example.com"}},
			},
			want: &model.App{Config: model.AppConfig{Domain: "example.com"}},
		},
		{
			name:   "returns ACLs for domain with trailing dot",
			domain: "example.com.",
			acls: map[string]model.App{
				"foo": {Config: model.AppConfig{Domain: "example.com"}},
			},
			want: &model.App{Config: model.AppConfig{Domain: "example.com"}},
		},
		{
			name:   "returns error for non-ascii domain",
			domain: "bücher.example.com",
			errorFunc: func(t *testing.T, e error) {
				assert.ErrorContains(t, e, "domain contains non-ascii characters")
			},
		},
		{
			name:   "returns ACLs with case-insensitive matching",
			domain: "Example.com",
			acls: map[string]model.App{
				"foo": {Config: model.AppConfig{Domain: "example.com"}},
			},
			want: &model.App{Config: model.AppConfig{Domain: "example.com"}},
		},
		{
			name:   "falls back to name matching when domain fails",
			domain: "app.example.com",
			acls: map[string]model.App{
				"app": {Path: model.AppPath{Allow: "/foo"}},
			},
			want: &model.App{Path: model.AppPath{Allow: "/foo"}},
		},
		{
			name:   "name matching is case-insensitive",
			domain: "aPp.example.com",
			acls: map[string]model.App{
				"APP": {Path: model.AppPath{Allow: "/foo"}},
			},
			want: &model.App{Path: model.AppPath{Allow: "/foo"}},
		},
		{
			name:   "returns nil when no ACLs are found",
			domain: "example.com",
			acls:   map[string]model.App{},
			want:   nil,
		},
		{
			name:   "App in domain not matching with the cookie domain should return nothing with name matching",
			domain: "foo.bad_example.com",
			acls: map[string]model.App{
				"foo": {
					Path: model.AppPath{Allow: "/foo"},
				},
			},
			want: nil,
		},
		{
			name:   "App in domain not matching with the cookie domain should return nothing with domain matching",
			domain: "foo.bad_example.com",
			acls: map[string]model.App{
				"foo": {
					Path:   model.AppPath{Allow: "/foo"},
					Config: model.AppConfig{Domain: "foo.bad_example.com"},
				},
			},
			want: nil,
		},
	}

	// run once for a mock provider
	for _, test := range tests {
		t.Run(test.name+"(getACLs)", func(t *testing.T) {
			mock := newMockProvider(test.acls, false)
			acls := NewAccessControlsService(AccessControlServiceInput{
				Log:           log,
				Runtime:       &runtime,
				Config:        &model.Config{},
				LabelProvider: mock,
			})
			app, err := acls.getACLs(test.domain, mock.Lookup)
			if test.errorFunc != nil {
				test.errorFunc(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.want, app)
		})
	}

	// run again for static acls
	for _, test := range tests {
		t.Run(test.name+"(staticACLs)", func(t *testing.T) {
			acls := NewAccessControlsService(AccessControlServiceInput{
				Log:     log,
				Runtime: &runtime,
				Config: &model.Config{
					Apps: test.acls,
				},
			})
			app, err := acls.lookupStaticACLs(test.domain)
			if test.errorFunc != nil {
				test.errorFunc(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.want, app)
		})
	}

	// get acls should return an error when the provider fails
	mock := newMockProvider(map[string]model.App{}, true)
	acls := NewAccessControlsService(AccessControlServiceInput{
		Log:     log,
		Runtime: &runtime,
		Config:  &model.Config{},
	})
	_, err := acls.getACLs("example.com", mock.Lookup)
	assert.Error(t, err)

	// get acls should return an error when multiple apps with the same domain exist
	acls = NewAccessControlsService(AccessControlServiceInput{
		Log:     log,
		Runtime: &runtime,
		Config: &model.Config{
			Apps: map[string]model.App{
				"foo":     {Path: model.AppPath{Allow: "/foo"}},
				"foo.bar": {Path: model.AppPath{Allow: "/bar"}},
			},
		},
	})
	_, err = acls.GetAccessControls("foo.bar.example.com")
	assert.ErrorContains(t, err, "domain matched multiple apps by name prefix, use explicit domain config")

	// get access controls should get acls from
	// static when static acls are configured
	acls = NewAccessControlsService(AccessControlServiceInput{
		Log:     log,
		Runtime: &runtime,
		Config: &model.Config{
			Apps: map[string]model.App{
				"foo": {Config: model.AppConfig{Domain: "foo.example.com"}},
			},
		},
	})
	app, err := acls.GetAccessControls("foo.example.com")
	require.NoError(t, err)
	assert.Equal(t, &model.App{Config: model.AppConfig{Domain: "foo.example.com"}}, app)

	// should return nil for no apps
	app, err = acls.GetAccessControls("bar.example.com")
	require.NoError(t, err)
	assert.Nil(t, app)

	// Should use label provider if available
	mock = newMockProvider(map[string]model.App{
		"bar": {
			Config: model.AppConfig{Domain: "bar.example.com"},
		},
	}, false)
	acls = NewAccessControlsService(AccessControlServiceInput{
		Log:           log,
		Runtime:       &runtime,
		Config:        &model.Config{},
		LabelProvider: mock,
	})
	app, err = acls.GetAccessControls("bar.example.com")
	require.NoError(t, err)
	assert.Equal(t, &model.App{Config: model.AppConfig{Domain: "bar.example.com"}}, app)
}
