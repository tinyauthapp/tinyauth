package service

import (
	"regexp"
	"strings"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

// For LDAP and OAuth groups and IP allow/deny, we default to allow even with a deny policy.
// This is because we can't force the user to use groups in LDAP and OAuth if they would like to use
// a deny policy. As for IP checks, we can't reliably get the client IP (most of Tinyauth instances are
// behind a Docker bridge network) so to make it easier for users to use a deny policy without
// issues with IPs we allow by default.

type RuleName string

const (
	RuleUserAllowed RuleName = "rule-user-allowed"
	RuleOAuthGroup  RuleName = "rule-oauth-group"
	RuleLDAPGroup   RuleName = "rule-ldap-group"
	RuleAuthEnabled RuleName = "rule-auth-enabled"
	RuleIPAllowed   RuleName = "rule-ip-allowed"
	RuleIPBypassed  RuleName = "rule-ip-bypassed"
)

type UserAllowedRule struct {
	Log *logger.Logger
}

func (rule *UserAllowedRule) Evaluate(ctx *ACLContext) Effect {
	if ctx.UserContext == nil {
		return EffectDeny
	}

	if ctx.ACLs == nil {
		return EffectAbstain
	}

	if ctx.UserContext.Provider == model.ProviderOAuth {
		rule.Log.App.Debug().Msg("User is an OAuth user, checking OAuth whitelist")
		match, err := utils.CheckFilter(ctx.ACLs.OAuth.Whitelist, ctx.UserContext.OAuth.Email)
		if err != nil {
			rule.Log.App.Warn().Err(err).Str("item", ctx.UserContext.OAuth.Email).Msg("Invalid entry in OAuth whitelist")
			return EffectDeny
		}
		if match {
			rule.Log.App.Debug().Str("email", ctx.UserContext.OAuth.Email).Msg("User is in OAuth whitelist, allowing access")
			return EffectAllow
		}
		return EffectDeny
	}

	if ctx.ACLs.Users.Block != "" {
		rule.Log.App.Debug().Msg("Checking users block list")
		match, err := utils.CheckFilter(ctx.ACLs.Users.Block, ctx.UserContext.GetUsername())
		if err != nil {
			rule.Log.App.Warn().Err(err).Str("item", ctx.UserContext.GetUsername()).Msg("Invalid entry in users block list")
			return EffectDeny
		}
		if match {
			rule.Log.App.Debug().Str("username", ctx.UserContext.GetUsername()).Msg("User is in users block list, denying access")
			return EffectDeny
		}
		return EffectAllow
	}

	rule.Log.App.Debug().Msg("Checking users allow list")

	match, err := utils.CheckFilter(ctx.ACLs.Users.Allow, ctx.UserContext.GetUsername())

	if err != nil {
		if err == utils.ErrFilterEmpty {
			return EffectAbstain
		}
		rule.Log.App.Warn().Err(err).Str("item", ctx.UserContext.GetUsername()).Msg("Invalid entry in users allow list")
		return EffectDeny
	}

	if match {
		rule.Log.App.Debug().Str("username", ctx.UserContext.GetUsername()).Msg("User is in users allow list, allowing access")
		return EffectAllow
	}

	rule.Log.App.Debug().Str("username", ctx.UserContext.GetUsername()).Msg("User is not in users allow list, denying access")
	return EffectDeny
}

type OAuthGroupRule struct {
	Log *logger.Logger
}

func (rule *OAuthGroupRule) Evaluate(ctx *ACLContext) Effect {
	if ctx.UserContext == nil {
		return EffectDeny
	}

	if ctx.ACLs == nil {
		return EffectAllow
	}

	if !ctx.UserContext.IsOAuth() {
		rule.Log.App.Debug().Msg("User is not an OAuth user, skipping OAuth group check")
		return EffectAllow
	}

	if len(ctx.ACLs.OAuth.Groups) == 0 {
		rule.Log.App.Debug().Msg("No OAuth groups specified in ACLs, allowing access")
		return EffectAllow
	}

	if _, ok := model.OverrideProviders[ctx.UserContext.OAuth.ID]; ok {
		rule.Log.App.Debug().Str("provider", ctx.UserContext.OAuth.ID).Msg("Provider override detected, skipping group check")
		return EffectAllow
	}

	for _, group := range ctx.UserContext.OAuth.Groups {
		match, err := utils.CheckFilter(ctx.ACLs.OAuth.Groups, strings.TrimSpace(group))
		if err != nil {
			rule.Log.App.Warn().Err(err).Str("item", group).Msg("Invalid entry in OAuth groups ACL")
			return EffectDeny
		}
		if match {
			rule.Log.App.Trace().Str("group", group).Str("required", ctx.ACLs.OAuth.Groups).Msg("User group matched, allowing access")
			return EffectAllow
		}
	}

	rule.Log.App.Debug().Msg("No groups matched")
	return EffectDeny
}

type LDAPGroupRule struct {
	Log *logger.Logger
}

func (rule *LDAPGroupRule) Evaluate(ctx *ACLContext) Effect {
	if ctx.UserContext == nil {
		return EffectDeny
	}

	if ctx.ACLs == nil {
		return EffectAllow
	}

	if !ctx.UserContext.IsLDAP() {
		rule.Log.App.Debug().Msg("User is not an LDAP user, skipping LDAP group check")
		return EffectAllow
	}

	if len(ctx.ACLs.LDAP.Groups) == 0 {
		rule.Log.App.Debug().Msg("No LDAP groups specified in ACLs, allowing access")
		return EffectAllow
	}

	for _, group := range ctx.UserContext.LDAP.Groups {
		match, err := utils.CheckFilter(ctx.ACLs.LDAP.Groups, strings.TrimSpace(group))
		if err != nil {
			rule.Log.App.Warn().Err(err).Str("item", group).Msg("Invalid entry in LDAP groups ACL")
			return EffectDeny
		}
		if match {
			rule.Log.App.Trace().Str("group", group).Str("required", ctx.ACLs.LDAP.Groups).Msg("User group matched, allowing access")
			return EffectAllow
		}
	}

	rule.Log.App.Debug().Msg("No groups matched")
	return EffectDeny
}

type AuthEnabledRule struct {
	Log *logger.Logger
}

func (rule *AuthEnabledRule) Evaluate(ctx *ACLContext) Effect {
	if ctx.ACLs == nil {
		return EffectDeny
	}

	if ctx.ACLs.Path.Block != "" {
		regex, err := regexp.Compile(ctx.ACLs.Path.Block)

		if err != nil {
			rule.Log.App.Error().Err(err).Msg("Failed to compile block regex")
			return EffectDeny
		}

		if !regex.MatchString(ctx.Path) {
			return EffectAllow
		}
	}

	if ctx.ACLs.Path.Allow != "" {
		regex, err := regexp.Compile(ctx.ACLs.Path.Allow)

		if err != nil {
			rule.Log.App.Error().Err(err).Msg("Failed to compile allow regex")
			return EffectDeny
		}

		if regex.MatchString(ctx.Path) {
			return EffectAllow
		}
	}

	return EffectDeny
}

type IPAllowedRule struct {
	Log    *logger.Logger
	Config model.Config
}

func (rule *IPAllowedRule) Evaluate(ctx *ACLContext) Effect {
	if !ctx.TrustedProxiesConfigured {
		return EffectAllow // We can't block the proxy
	}

	// merge global and per-app block/allow lists
	blockedIps := append([]string{}, rule.Config.Auth.IP.Block...)
	allowedIPs := append([]string{}, rule.Config.Auth.IP.Allow...)

	if ctx.ACLs != nil {
		blockedIps = append(blockedIps, ctx.ACLs.IP.Block...)
		allowedIPs = append(allowedIPs, ctx.ACLs.IP.Allow...)
	}

	for _, blocked := range blockedIps {
		match, err := utils.CheckIPFilter(blocked, ctx.IP.String())
		if err != nil {
			rule.Log.App.Warn().Err(err).Str("item", blocked).Msg("Invalid IP/CIDR in block list")
			continue
		}
		if match {
			rule.Log.App.Debug().Str("ip", ctx.IP.String()).Str("item", blocked).Msg("IP is in block list, denying access")
			return EffectDeny
		}
	}

	for _, allowed := range allowedIPs {
		match, err := utils.CheckIPFilter(allowed, ctx.IP.String())
		if err != nil {
			rule.Log.App.Warn().Err(err).Str("item", allowed).Msg("Invalid IP/CIDR in allow list")
			continue
		}
		if match {
			rule.Log.App.Debug().Str("ip", ctx.IP.String()).Str("item", allowed).Msg("IP is in allow list, allowing access")
			return EffectAllow
		}
	}

	if len(allowedIPs) > 0 {
		rule.Log.App.Debug().Str("ip", ctx.IP.String()).Msg("IP not in allow list, denying access")
		return EffectDeny
	}

	rule.Log.App.Debug().Str("ip", ctx.IP.String()).Msg("IP not in block or allow list, allowing access")
	return EffectAllow
}

type IPBypassedRule struct {
	Log    *logger.Logger
	Config model.Config
}

func (rule *IPBypassedRule) Evaluate(ctx *ACLContext) Effect {
	if !ctx.TrustedProxiesConfigured {
		return EffectDeny
	}

	// merge global and per-app bypass lists
	bypassList := append([]string{}, rule.Config.Auth.IP.Bypass...)
	if ctx.ACLs != nil {
		bypassList = append(bypassList, ctx.ACLs.IP.Bypass...)
	}

	for _, bypassed := range bypassList {
		match, err := utils.CheckIPFilter(bypassed, ctx.IP.String())
		if err != nil {
			rule.Log.App.Warn().Err(err).Str("item", bypassed).Msg("Invalid IP/CIDR in bypass list")
			continue
		}
		if match {
			rule.Log.App.Debug().Str("ip", ctx.IP.String()).Str("item", bypassed).Msg("IP is in bypass list, skipping authentication")
			return EffectAllow
		}
	}

	rule.Log.App.Debug().Str("ip", ctx.IP.String()).Msg("IP not in bypass list, proceeding with authentication")
	return EffectDeny
}
