package service

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

type mockLabelProvider struct {
	getLabelsFn func(appDomain string) (*model.App, error)
	calledWith  string
	callCount   int
}

func (m *mockLabelProvider) GetLabels(appDomain string) (*model.App, error) {
	m.calledWith = appDomain
	m.callCount++
	if m.getLabelsFn != nil {
		return m.getLabelsFn(appDomain)
	}
	return nil, nil
}

func TestLookupStaticACLs(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	tests := []struct {
		name           string
		apps           map[string]model.App
		domain         string
		expectNil      bool
		expectedDomain string
	}{
		{
			name:      "returns nil when no apps are configured",
			apps:      nil,
			domain:    "foo.example.com",
			expectNil: true,
		},
		{
			name: "returns nil when no app matches",
			apps: map[string]model.App{
				"foo": {Config: model.AppConfig{Domain: "foo.example.com"}},
			},
			domain:    "bar.example.com",
			expectNil: true,
		},
		{
			name: "matches by exact domain",
			apps: map[string]model.App{
				"foo": {Config: model.AppConfig{Domain: "foo.example.com"}},
			},
			domain:         "foo.example.com",
			expectedDomain: "foo.example.com",
		},
		{
			name: "matches by app name when domain does not match any app",
			apps: map[string]model.App{
				"foo": {Config: model.AppConfig{Domain: "configured.example.com"}},
			},
			domain:         "foo.example.com",
			expectedDomain: "configured.example.com",
		},
		{
			name: "matches by app name for nested subdomains",
			apps: map[string]model.App{
				"foo": {Config: model.AppConfig{Domain: "configured.example.com"}},
			},
			domain:         "foo.sub.example.com",
			expectedDomain: "configured.example.com",
		},
		{
			name: "selects the app matching by domain among multiple apps",
			apps: map[string]model.App{
				"unrelated": {Config: model.AppConfig{Domain: "other.example.com"}},
				"target":    {Config: model.AppConfig{Domain: "foo.example.com"}},
			},
			domain:         "foo.example.com",
			expectedDomain: "foo.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewAccessControlsService(log, model.Config{Apps: tt.apps}, nil)
			got := svc.lookupStaticACLs(tt.domain)
			if tt.expectNil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tt.expectedDomain, got.Config.Domain)
		})
	}
}

func TestGetAccessControls(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	t.Run("returns static ACLs when domain matches", func(t *testing.T) {
		config := model.Config{
			Apps: map[string]model.App{
				"foo": {
					Config: model.AppConfig{Domain: "foo.example.com"},
					Users:  model.AppUsers{Allow: "alice"},
				},
			},
		}
		svc := NewAccessControlsService(log, config, nil)

		got, err := svc.GetAccessControls("foo.example.com")

		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "foo.example.com", got.Config.Domain)
		assert.Equal(t, "alice", got.Users.Allow)
	})

	t.Run("returns nil when no static match and no label provider", func(t *testing.T) {
		svc := NewAccessControlsService(log, model.Config{}, nil)

		got, err := svc.GetAccessControls("unknown.example.com")

		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("returns nil when label provider pointer wraps a nil interface", func(t *testing.T) {
		var provider LabelProvider
		svc := NewAccessControlsService(log, model.Config{}, &provider)

		got, err := svc.GetAccessControls("unknown.example.com")

		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("falls back to label provider when no static match", func(t *testing.T) {
		expected := &model.App{
			Config: model.AppConfig{Domain: "dynamic.example.com"},
			Users:  model.AppUsers{Allow: "bob"},
		}
		mock := &mockLabelProvider{
			getLabelsFn: func(appDomain string) (*model.App, error) {
				return expected, nil
			},
		}
		var provider LabelProvider = mock
		svc := NewAccessControlsService(log, model.Config{}, &provider)

		got, err := svc.GetAccessControls("dynamic.example.com")

		require.NoError(t, err)
		assert.Same(t, expected, got)
		assert.Equal(t, "dynamic.example.com", mock.calledWith)
		assert.Equal(t, 1, mock.callCount)
	})

	t.Run("does not call label provider when static match found", func(t *testing.T) {
		mock := &mockLabelProvider{}
		var provider LabelProvider = mock
		config := model.Config{
			Apps: map[string]model.App{
				"foo": {Config: model.AppConfig{Domain: "foo.example.com"}},
			},
		}
		svc := NewAccessControlsService(log, config, &provider)

		got, err := svc.GetAccessControls("foo.example.com")

		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "foo.example.com", got.Config.Domain)
		assert.Equal(t, 0, mock.callCount)
	})

	t.Run("propagates label provider errors", func(t *testing.T) {
		providerErr := errors.New("provider boom")
		mock := &mockLabelProvider{
			getLabelsFn: func(appDomain string) (*model.App, error) {
				return nil, providerErr
			},
		}
		var provider LabelProvider = mock
		svc := NewAccessControlsService(log, model.Config{}, &provider)

		got, err := svc.GetAccessControls("dynamic.example.com")

		assert.Nil(t, got)
		assert.ErrorIs(t, err, providerErr)
		assert.Equal(t, 1, mock.callCount)
	})
}
