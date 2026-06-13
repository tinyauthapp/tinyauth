package service

import (
	"strings"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

type LabelProvider interface {
	GetLabels(appDomain string) (*model.App, error)
}

type AccessControlsService struct {
	log           *logger.Logger
	config        model.Config
	labelProvider *LabelProvider
}

func NewAccessControlsService(
	log *logger.Logger,
	config model.Config,
	labelProvider *LabelProvider) *AccessControlsService {

	return &AccessControlsService{
		log:           log,
		config:        config,
		labelProvider: labelProvider,
	}
}

func (service *AccessControlsService) lookupStaticACLs(domain string) *model.App {
	var nameMatch *model.App

	// First try to find a matching app by domain, then fallback to matching by app name (subdomain)
	for app, config := range service.config.Apps {
		if config.Config.Domain == domain {
			service.log.App.Debug().Str("name", app).Msg("Found matching container by domain")
			return &config
		}
		if strings.SplitN(domain, ".", 2)[0] == app {
			service.log.App.Debug().Str("name", app).Msg("Found matching container by app name")
			nameMatch = &config
		}
	}

	return nameMatch
}

func (service *AccessControlsService) GetAccessControls(domain string) (*model.App, error) {
	// First check in the static config
	app := service.lookupStaticACLs(domain)

	if app != nil {
		service.log.App.Debug().Msg("Using static ACLs for app")
		return service.resolveAppOAuthWhitelist(app)
	}

	// If we have a label provider configured, try to get ACLs from it
	if service.labelProvider != nil && *service.labelProvider != nil {
		app, err := (*service.labelProvider).GetLabels(domain)
		if err != nil {
			return nil, err
		}
		return service.resolveAppOAuthWhitelist(app)
	}

	// no labels
	return nil, nil
}

func (service *AccessControlsService) resolveAppOAuthWhitelist(app *model.App) (*model.App, error) {
	if app == nil || app.OAuth.WhitelistFile == "" {
		return app, nil
	}

	values, err := utils.GetStringList([]string{app.OAuth.Whitelist}, app.OAuth.WhitelistFile)
	if err != nil {
		return nil, err
	}

	resolved := *app
	resolved.OAuth.Whitelist = strings.Join(values, ",")
	return &resolved, nil
}
