package service_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/test"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

// Create test rule
type TestRule struct{}

func (rule *TestRule) Evaluate(ctx *service.ACLContext) service.Effect {
	switch ctx.Path {
	case "/allowed":
		return service.EffectAllow
	case "/denied":
		return service.EffectDeny
	default:
		return service.EffectAbstain
	}
}

func TestPolicyEngine(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	cfg, _ := test.CreateTestConfigs(t)

	testRule := &TestRule{}

	// Engine should fail with invalid policy
	cfg.Auth.ACLs.Policy = "invalid_policy"
	_, err := service.NewPolicyEngine(service.PolicyEngineInput{
		Log:    log,
		Config: &cfg,
	})
	assert.Error(t, err)

	// Engine should initialize with 'allow' policy
	cfg.Auth.ACLs.Policy = string(service.PolicyAllow)
	engine, err := service.NewPolicyEngine(service.PolicyEngineInput{
		Log:    log,
		Config: &cfg,
	})
	assert.NoError(t, err)
	assert.Equal(t, service.PolicyAllow, engine.Policy())

	// Engine should initialize with 'deny' policy
	cfg.Auth.ACLs.Policy = string(service.PolicyDeny)
	engine, err = service.NewPolicyEngine(service.PolicyEngineInput{
		Log:    log,
		Config: &cfg,
	})
	assert.NoError(t, err)
	assert.Equal(t, service.PolicyDeny, engine.Policy())

	// Engine should allow adding rules
	engine, err = service.NewPolicyEngine(service.PolicyEngineInput{
		Log:    log,
		Config: &cfg,
	})
	assert.NoError(t, err)
	engine.RegisterRule("test-rule", testRule)
	_, ok := engine.Rules()["test-rule"]
	assert.True(t, ok)

	// Begin allow policy tests
	cfg.Auth.ACLs.Policy = string(service.PolicyAllow)
	engine, err = service.NewPolicyEngine(service.PolicyEngineInput{
		Log:    log,
		Config: &cfg,
	})
	assert.NoError(t, err)
	engine.RegisterRule("test-rule", testRule)

	// With allow policy, if rule allows, access should be allowed
	ctx := &service.ACLContext{Path: "/allowed"}
	assert.Equal(t, true, engine.Evaluate("test-rule", ctx))

	// With allow policy, if rule denies, access should be denied
	ctx.Path = "/denied"
	assert.Equal(t, false, engine.Evaluate("test-rule", ctx))

	// With allow policy, if rule abstains, access should be allowed (default)
	ctx.Path = "/abstain"
	assert.Equal(t, true, engine.Evaluate("test-rule", ctx))

	// Begin deny policy tests
	cfg.Auth.ACLs.Policy = string(service.PolicyDeny)
	engine, err = service.NewPolicyEngine(service.PolicyEngineInput{
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
