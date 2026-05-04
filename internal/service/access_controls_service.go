package service

import (
	"errors"
	"strings"

	"github.com/tinyauthapp/tinyauth/internal/config"
	"github.com/tinyauthapp/tinyauth/internal/utils/tlog"
)

type LabelProvider interface {
	GetLabels(appDomain string) (config.App, error)
}

type AccessControlsService struct {
	labelProvider LabelProvider
	static        map[string]config.App
}

func NewAccessControlsService(labelProvider LabelProvider, static map[string]config.App) *AccessControlsService {
	return &AccessControlsService{
		labelProvider: labelProvider,
		static:        static,
	}
}

func (acls *AccessControlsService) Init() error {
	return nil // No initialization needed
}

func (acls *AccessControlsService) lookupStaticACLs(domain string) (config.App, error) {
	for app, config := range acls.static {
		if config.Config.Domain == domain {
			tlog.App.Debug().Str("name", app).Msg("Found matching container by domain")
			return config, nil
		}

		if strings.SplitN(domain, ".", 2)[0] == app {
			tlog.App.Debug().Str("name", app).Msg("Found matching container by app name")
			return config, nil
		}
	}
	return config.App{}, errors.New("no results")
}

func (acls *AccessControlsService) GetAccessControls(domain string) (config.App, error) {
	// First check in the static config
	app, err := acls.lookupStaticACLs(domain)

	if err == nil {
		tlog.App.Debug().Msg("Using ACls from static configuration")
		return app, nil
	}

	// Fallback to label provider
	tlog.App.Debug().Msg("Falling back to label provider for ACLs")
	return acls.labelProvider.GetLabels(domain)
}
