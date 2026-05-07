package loaders

import (
	"fmt"
	"os"

	"github.com/tinyauthapp/paerser/cli"
	"github.com/tinyauthapp/paerser/env"
	"github.com/tinyauthapp/tinyauth/internal/model"
)

type EnvLoader struct{}

func (e *EnvLoader) Load(_ []string, cmd *cli.Command) (bool, error) {
	vars := env.FindPrefixedEnvVars(os.Environ(), model.DefaultNamePrefix, cmd.Configuration)
	if len(vars) == 0 {
		return false, nil
	}

	if err := env.Decode(vars, model.DefaultNamePrefix, cmd.Configuration); err != nil {
		return false, fmt.Errorf("failed to decode configuration from environment variables: %w", err)
	}

	return true, nil
}
