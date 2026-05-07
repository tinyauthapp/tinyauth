package main

import (
	"fmt"

	"charm.land/huh/v2"
	"github.com/tinyauthapp/tinyauth/internal/bootstrap"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/loaders"
	"github.com/tinyauthapp/tinyauth/internal/utils/tlog"

	"github.com/rs/zerolog/log"
	"github.com/tinyauthapp/paerser/cli"
)

func main() {
	tConfig := model.NewDefaultConfiguration()

	loaders := []cli.ResourceLoader{
		&loaders.FileLoader{},
		&loaders.FlagLoader{},
		&loaders.EnvLoader{},
	}

	cmdTinyauth := &cli.Command{
		Name:          "tinyauth",
		Description:   "The simplest way to protect your apps with a login screen",
		Configuration: tConfig,
		Resources:     loaders,
		Run: func(_ []string) error {
			return runCmd(*tConfig)
		},
	}

	cmdUser := &cli.Command{
		Name:        "user",
		Description: "Manage Tinyauth users",
	}

	cmdTotp := &cli.Command{
		Name:        "totp",
		Description: "Manage Tinyauth TOTP users",
	}

	cmdOidc := &cli.Command{
		Name:        "oidc",
		Description: "Manage Tinyauth OIDC clients",
	}

	err := cmdTinyauth.AddCommand(versionCmd())

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to add version command")
	}

	err = cmdUser.AddCommand(verifyUserCmd())

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to add verify command")
	}

	err = cmdTinyauth.AddCommand(healthcheckCmd())

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to add healthcheck command")
	}

	err = cmdTotp.AddCommand(generateTotpCmd())

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to add generate command")
	}

	err = cmdUser.AddCommand(createUserCmd())

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to add create command")
	}

	err = cmdOidc.AddCommand(createOidcClientCmd())

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to add create command")
	}

	err = cmdTinyauth.AddCommand(cmdUser)

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to add user command")
	}

	err = cmdTinyauth.AddCommand(cmdTotp)

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to add totp command")
	}

	err = cmdTinyauth.AddCommand(cmdOidc)

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to add oidc command")
	}

	err = cli.Execute(cmdTinyauth)

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to execute command")
	}
}

func runCmd(cfg model.Config) error {
	logger := tlog.NewLogger(cfg.Log)
	logger.Init()

	tlog.App.Info().Str("version", model.Version).Msg("Starting tinyauth")

	app := bootstrap.NewBootstrapApp(cfg)

	err := app.Setup()

	if err != nil {
		return fmt.Errorf("failed to bootstrap app: %w", err)
	}

	return nil
}

type themeBase struct{}

func (t *themeBase) Theme(isDark bool) *huh.Styles {
	return huh.ThemeBase(isDark)
}
