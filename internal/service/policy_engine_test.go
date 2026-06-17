package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tinyauthapp/tinyauth/internal/test"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

// Create test rule
type TestRule struct{}

func (rule *TestRule) Evaluate(ctx *ACLContext) Effect {
	switch ctx.Path {
	case "/allowed":
		return EffectAllow
	case "/denied":
		return EffectDeny
	default:
		return EffectAbstain
	}
}

func TestPolicyEngine(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	cfg, _ := test.CreateTestConfigs(t)

	testRule := &TestRule{}

	// Engine should fail with invalid policy
	cfg.Auth.ACLs.Policy = "invalid_policy"
	_, err := NewPolicyEngine(PolicyEngineInput{
		Log:    log,
		Config: &cfg,
	})
	assert.Error(t, err)

	// Engine should initialize with 'allow' policy
	cfg.Auth.ACLs.Policy = string(PolicyAllow)
	engine, err := NewPolicyEngine(PolicyEngineInput{
		Log:    log,
		Config: &cfg,
	})
	assert.NoError(t, err)
	assert.Equal(t, PolicyAllow, engine.Policy())

	// Engine should initialize with 'deny' policy
	cfg.Auth.ACLs.Policy = string(PolicyDeny)
	engine, err = NewPolicyEngine(PolicyEngineInput{
		Log:    log,
		Config: &cfg,
	})
	assert.NoError(t, err)
	assert.Equal(t, PolicyDeny, engine.Policy())

	// Engine should allow adding rules
	engine, err = NewPolicyEngine(PolicyEngineInput{
		Log:    log,
		Config: &cfg,
	})
	assert.NoError(t, err)
	engine.RegisterRule("test-rule", testRule)
	_, ok := engine.Rules()["test-rule"]
	assert.True(t, ok)

	// Begin allow policy tests
	cfg.Auth.ACLs.Policy = string(PolicyAllow)
	engine, err = NewPolicyEngine(PolicyEngineInput{
		Log:    log,
		Config: &cfg,
	})
	assert.NoError(t, err)
	engine.RegisterRule("test-rule", testRule)

	// With allow policy, if rule allows, access should be allowed
	ctx := &ACLContext{Path: "/allowed"}
	assert.Equal(t, true, engine.Evaluate("test-rule", ctx))

	// With allow policy, if rule denies, access should be denied
	ctx.Path = "/denied"
	assert.Equal(t, false, engine.Evaluate("test-rule", ctx))

	// With allow policy, if rule abstains, access should be allowed (default)
	ctx.Path = "/abstain"
	assert.Equal(t, true, engine.Evaluate("test-rule", ctx))

	// Begin deny policy tests
	cfg.Auth.ACLs.Policy = string(PolicyDeny)
	engine, err = NewPolicyEngine(PolicyEngineInput{
		Log:    log,
		Config: &cfg,
	})
	assert.NoError(t, err)
	engine.RegisterRule("test-rule", testRule)

	// With deny policy, if rule allows, access should be allowed
	ctx.Path = "/allowed"
	assert.Equal(t, true, engine.Evaluate("test-rule", ctx))

	// With deny policy, if rule denies, access should be denied
	ctx.Path = "/denied"
	assert.Equal(t, false, engine.Evaluate("test-rule", ctx))

	// With deny policy, if rule abstains, access should be denied (default)
	ctx.Path = "/abstain"
	assert.Equal(t, false, engine.Evaluate("test-rule", ctx))
}
