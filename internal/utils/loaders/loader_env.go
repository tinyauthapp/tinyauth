package loaders

import (
	"fmt"
	"os"

	"github.com/tinyauthapp/tinyauth/internal/config"

	"github.com/tinyauthapp/paerser/cli"
	"github.com/tinyauthapp/paerser/env"
)

type EnvLoader struct{}

func (e *EnvLoader) Load(_ []string, cmd *cli.Command) (bool, error) {
	vars := env.FindPrefixedEnvVars(os.Environ(), config.DefaultNamePrefix, cmd.Configuration)
	if len(vars) == 0 {
		return false, nil
	}

	if err := env.Decode(vars, config.DefaultNamePrefix, cmd.Configuration); err != nil {
		return false, fmt.Errorf("failed to decode configuration from environment variables: %w", err)
	}

	return true, nil
}
