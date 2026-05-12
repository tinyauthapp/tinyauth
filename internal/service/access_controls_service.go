package service

import (
	"regexp"
	"strings"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

type AccessControlPolicy string

const (
	PolicyAllow AccessControlPolicy = "allow"
	PolicyBlock AccessControlPolicy = "block"
)

func accessControlPolicyFromString(s string) (AccessControlPolicy, bool) {
	switch strings.ToLower(s) {
	case "allow":
		return PolicyAllow, true
	case "block":
		return PolicyBlock, true
	default:
		return "", false
	}
}

type LabelProvider interface {
	GetLabels(appDomain string) (*model.App, error)
}

type AccessControlsService struct {
	log           *logger.Logger
	config        model.Config
	labelProvider *LabelProvider
	policy        AccessControlPolicy
}

func NewAccessControlsService(
	log *logger.Logger,
	config model.Config,
	labelProvider *LabelProvider) *AccessControlsService {

	service := AccessControlsService{
		log:           log,
		config:        config,
		labelProvider: labelProvider,
	}

	policy, ok := accessControlPolicyFromString(config.Auth.ACLS.Policy)

	if !ok {
		log.App.Warn().Str("policy", config.Auth.ACLS.Policy).Msg("Invalid ACL policy in config, defaulting to 'allow'")
		service.policy = PolicyAllow
	}

	if policy == PolicyAllow {
		log.App.Debug().Msg("Using 'allow' ACL policy: access to apps will be allowed by default unless explicitly blocked")
	} else {
		log.App.Debug().Msg("Using 'block' ACL policy: access to apps will be blocked by default unless explicitly allowed")
	}

	service.policy = policy

	return &service
}

func (service *AccessControlsService) lookupStaticACLs(domain string) *model.App {
	var appAcls *model.App
	for app, config := range service.config.Apps {
		if config.Config.Domain == domain {
			service.log.App.Debug().Str("name", app).Msg("Found matching container by domain")
			appAcls = &config
			break // If we find a match by domain, we can stop searching
		}

		if strings.SplitN(domain, ".", 2)[0] == app {
			service.log.App.Debug().Str("name", app).Msg("Found matching container by app name")
			appAcls = &config
			break // If we find a match by app name, we can stop searching
		}
	}
	return appAcls
}

func (service *AccessControlsService) GetAccessControls(domain string) (*model.App, error) {
	// First check in the static config
	app := service.lookupStaticACLs(domain)

	if app != nil {
		service.log.App.Debug().Msg("Using static ACLs for app")
		return app, nil
	}

	// If we have a label provider configured, try to get ACLs from it
	if service.labelProvider != nil {
		return (*service.labelProvider).GetLabels(domain)
	}

	// no labels
	return nil, nil
}

func (service *AccessControlsService) IsUserAllowed(context model.UserContext, acls *model.App) bool {
	if acls == nil {
		return service.policyResult(true)
	}

	if context.Provider == model.ProviderOAuth {
		service.log.App.Debug().Msg("User is an OAuth user, checking OAuth whitelist")
		return utils.CheckFilter(acls.OAuth.Whitelist, context.OAuth.Email)
	}

	if acls.Users.Block != "" {
		service.log.App.Debug().Msg("Checking users block list")
		if utils.CheckFilter(acls.Users.Block, context.GetUsername()) {
			return false
		}
	}

	service.log.App.Debug().Msg("Checking users allow list")
	return utils.CheckFilter(acls.Users.Allow, context.GetUsername())
}

func (service *AccessControlsService) IsInOAuthGroup(context model.UserContext, acls *model.App) bool {
	if acls == nil {
		return true
	}

	if !context.IsOAuth() {
		service.log.App.Debug().Msg("User is not an OAuth user, skipping OAuth group check")
		return false
	}

	if _, ok := model.OverrideProviders[context.OAuth.ID]; ok {
		service.log.App.Debug().Str("provider", context.OAuth.ID).Msg("Provider override detected, skipping group check")
		return true
	}

	for _, userGroup := range context.OAuth.Groups {
		if utils.CheckFilter(acls.OAuth.Groups, strings.TrimSpace(userGroup)) {
			service.log.App.Trace().Str("group", userGroup).Str("required", acls.OAuth.Groups).Msg("User group matched")
			return true
		}
	}

	service.log.App.Debug().Msg("No groups matched")
	return false
}

func (service *AccessControlsService) IsInLDAPGroup(context model.UserContext, acls *model.App) bool {
	if acls == nil {
		return true
	}

	if !context.IsLDAP() {
		service.log.App.Debug().Msg("User is not an LDAP user, skipping LDAP group check")
		return false
	}

	for _, userGroup := range context.LDAP.Groups {
		if utils.CheckFilter(acls.LDAP.Groups, strings.TrimSpace(userGroup)) {
			service.log.App.Trace().Str("group", userGroup).Str("required", acls.LDAP.Groups).Msg("User group matched")
			return true
		}
	}

	service.log.App.Debug().Msg("No groups matched")
	return false
}

func (service *AccessControlsService) IsAuthEnabled(uri string, acls *model.App) bool {
	if acls == nil {
		return true
	}

	if acls.Path.Block != "" {
		regex, err := regexp.Compile(acls.Path.Block)

		if err != nil {
			service.log.App.Error().Err(err).Msg("Failed to compile block regex")
			return true
		}

		if !regex.MatchString(uri) {
			return false
		}
	}

	if acls.Path.Allow != "" {
		regex, err := regexp.Compile(acls.Path.Allow)

		if err != nil {
			service.log.App.Error().Err(err).Msg("Failed to compile allow regex")
			return true
		}

		if regex.MatchString(uri) {
			return false
		}
	}

	return true
}

func (service *AccessControlsService) IsIPAllowed(ip string, acls *model.App) bool {
	if acls == nil {
		return service.policyResult(true)
	}

	// Merge the global and app IP filter
	blockedIps := append(service.config.Auth.IP.Block, acls.IP.Block...)
	allowedIPs := append(service.config.Auth.IP.Allow, acls.IP.Allow...)

	for _, blocked := range blockedIps {
		res, err := utils.FilterIP(blocked, ip)
		if err != nil {
			service.log.App.Warn().Err(err).Str("item", blocked).Msg("Invalid IP/CIDR in block list")
			continue
		}
		if res {
			service.log.App.Debug().Str("ip", ip).Str("item", blocked).Msg("IP is in block list, denying access")
			return false
		}
	}

	for _, allowed := range allowedIPs {
		res, err := utils.FilterIP(allowed, ip)
		if err != nil {
			service.log.App.Warn().Err(err).Str("item", allowed).Msg("Invalid IP/CIDR in allow list")
			continue
		}
		if res {
			service.log.App.Debug().Str("ip", ip).Str("item", allowed).Msg("IP is in allow list, allowing access")
			return true
		}
	}

	if len(allowedIPs) > 0 {
		service.log.App.Debug().Str("ip", ip).Msg("IP not in allow list, denying access")
		return false
	}

	service.log.App.Debug().Str("ip", ip).Msg("IP not in block or allow list, allowing access")
	return service.policyResult(true)
}

func (service *AccessControlsService) IsIPBypassed(ip string, acls *model.App) bool {
	if acls == nil {
		return false
	}

	for _, bypassed := range acls.IP.Bypass {
		res, err := utils.FilterIP(bypassed, ip)
		if err != nil {
			service.log.App.Warn().Err(err).Str("item", bypassed).Msg("Invalid IP/CIDR in bypass list")
			continue
		}
		if res {
			service.log.App.Debug().Str("ip", ip).Str("item", bypassed).Msg("IP is in bypass list, skipping authentication")
			return true
		}
	}

	service.log.App.Debug().Str("ip", ip).Msg("IP not in bypass list, proceeding with authentication")
	return false
}

func (service *AccessControlsService) policyResult(result bool) bool {
	if service.policy == PolicyAllow {
		return result
	} else {
		return !result
	}
}
