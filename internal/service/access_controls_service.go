package service

import (
	"strings"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/tlog"
)

type LabelProvider interface {
	GetLabels(appDomain string) (*model.App, error)
}

type AccessControlsService struct {
	labelProvider LabelProvider
	static        map[string]model.App
}

func NewAccessControlsService(labelProvider LabelProvider, static map[string]model.App) *AccessControlsService {
	return &AccessControlsService{
		labelProvider: labelProvider,
		static:        static,
	}
}

func (acls *AccessControlsService) Init() error {
	return nil // No initialization needed
}

func (acls *AccessControlsService) lookupStaticACLs(domain string) *model.App {
	var appAcls *model.App
	for app, config := range acls.static {
		if config.Config.Domain == domain {
			tlog.App.Debug().Str("name", app).Msg("Found matching container by domain")
			appAcls = &config
			break // If we find a match by domain, we can stop searching
		}

		if strings.SplitN(domain, ".", 2)[0] == app {
			tlog.App.Debug().Str("name", app).Msg("Found matching container by app name")
			appAcls = &config
			break // If we find a match by app name, we can stop searching
		}
	}
	return appAcls
}

func (acls *AccessControlsService) GetAccessControls(domain string) (*model.App, error) {
	// First check in the static config
	app := acls.lookupStaticACLs(domain)

	if app != nil {
		tlog.App.Debug().Msg("Using ACls from static configuration")
		return app, nil
	}

	// Fallback to label provider
	tlog.App.Debug().Msg("Falling back to label provider for ACLs")
	return acls.labelProvider.GetLabels(domain)
}
