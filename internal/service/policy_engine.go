package service

import (
	"fmt"
	"net"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

type Effect int

const (
	EffectAbstain Effect = iota
	EffectAllow
	EffectDeny
)

type Rule interface {
	Evaluate(ctx *ACLContext) Effect
}

type ACLContext struct {
	ACLs        *model.App
	UserContext *model.UserContext
	IP          net.IP
	Path        string
}

type PolicyEngine struct {
	log    *logger.Logger
	rules  map[RuleName]Rule
	policy model.Policy
}

func NewPolicyEngine(config model.Config, log *logger.Logger) (*PolicyEngine, error) {
	engine := PolicyEngine{
		log:   log,
		rules: make(map[RuleName]Rule),
	}

	switch config.Auth.ACLs.Policy {
	case string(model.PolicyAllow):
		log.App.Debug().Msg("Using 'allow' ACL policy: access to apps will be allowed by default unless explicitly blocked")
		engine.policy = model.PolicyAllow
	case string(model.PolicyDeny):
		log.App.Debug().Msg("Using 'deny' ACL policy: access to apps will be blocked by default unless explicitly allowed")
		engine.policy = model.PolicyDeny
	default:
		return nil, fmt.Errorf("invalid acl policy: %s", config.Auth.ACLs.Policy)
	}

	return &engine, nil
}

func (engine *PolicyEngine) RegisterRule(name RuleName, rule Rule) {
	engine.log.App.Debug().Str("rule", string(name)).Msg("Registering ACL rule in policy engine")
	engine.rules[name] = rule
}

func (engine *PolicyEngine) evaluateRuleByName(name RuleName, ctx *ACLContext) Effect {
	rule, exists := engine.rules[name]

	if !exists {
		engine.log.App.Warn().Str("rule", string(name)).Msg("Rule not found in policy engine, defaulting to deny")
		return EffectDeny
	}

	return rule.Evaluate(ctx)
}

func (engine *PolicyEngine) effectToAccess(effect Effect) bool {
	switch effect {
	case EffectAllow:
		return true
	case EffectDeny:
		return false
	default:
		// If the effect is abstain, we fall back to the default policy
		return engine.policy == model.PolicyAllow
	}
}

func (engine *PolicyEngine) Evaluate(name RuleName, ctx *ACLContext) bool {
	effect := engine.evaluateRuleByName(name, ctx)
	access := engine.effectToAccess(effect)

	engine.log.App.Debug().
		Str("rule", string(name)).
		Int("effect", int(effect)).
		Bool("access", access).
		Msg("Evaluated ACL rule")

	return access
}

func (engine *PolicyEngine) Policy() model.Policy {
	return engine.policy
}

func (engine *PolicyEngine) Rules() map[RuleName]Rule {
	return engine.rules
}

func (engine *PolicyEngine) EvaluateFunc(f func() Effect) bool {
	return engine.effectToAccess(f())
}
