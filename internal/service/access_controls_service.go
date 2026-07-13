package service

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"go.uber.org/dig"
)

type LabelProvider interface {
	GetLabels(appDomain string) (*model.App, error)
}

type AccessControlsService struct {
	log           *logger.Logger
	config        *model.Config
	labelProvider LabelProvider
}

type AccessControlServiceInput struct {
	dig.In

	Log           *logger.Logger
	Config        *model.Config
	LabelProvider LabelProvider `optional:"true"`
}

func NewAccessControlsService(i AccessControlServiceInput) *AccessControlsService {

	return &AccessControlsService{
		log:           i.Log,
		config:        i.Config,
		labelProvider: i.LabelProvider,
	}
}

func (service *AccessControlsService) lookupStaticACLs(domain string) (*model.App, error) {
	var nameMatch *model.App

	// First try to find a matching app by domain, then fallback to matching by app name (subdomain)
	for app, config := range service.config.Apps {
		match, err := service.checkDomain(domain, config.Config.Domain)
		if err != nil {
			return nil, err
		}
		if match {
			service.log.App.Debug().Str("name", app).Msg("Found matching container by domain")
			return &config, nil
		}
		if strings.HasPrefix(domain, app+".") {
			service.log.App.Debug().Str("name", app).Msg("Found matching container by app name")
			nameMatch = &config
		}
	}

	return nameMatch, nil
}

func (service *AccessControlsService) GetAccessControls(domain string) (*model.App, error) {
	// First check in the static config
	app, err := service.lookupStaticACLs(domain)

	if err != nil {
		return nil, err
	}

	if app != nil {
		service.log.App.Debug().Msg("Using static ACLs for app")
		return app, nil
	}

	// If we have a label provider configured, try to get ACLs from it
	if service.labelProvider != nil {
		return service.labelProvider.GetLabels(domain)
	}

	// no labels
	return nil, nil
}

func (service *AccessControlsService) checkDomain(check, target string) (bool, error) {
	// Domains don't have a scheme, so we use a mock one
	cu, err := url.Parse("tinyauth://" + check)

	if err != nil {
		return false, fmt.Errorf("failed to parse check domain: %w", err)
	}

	if cu.Host == "" {
		return false, fmt.Errorf("check domain is empty")
	}

	tu, err := url.Parse("tinyauth://" + target)

	if err != nil {
		return false, fmt.Errorf("failed to parse target domain: %w", err)
	}

	if tu.Host == "" {
		return false, fmt.Errorf("target domain is empty")
	}

	// non-dns check url
	ndcu := strings.TrimSuffix(cu.Hostname(), ".")

	// non-dns target url
	ndtu := strings.TrimSuffix(tu.Hostname(), ".")

	// Strip out the port
	return strings.EqualFold(ndcu, ndtu), nil
}
