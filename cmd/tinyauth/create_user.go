package main

import (
	"errors"
	"fmt"
	"strings"

	"charm.land/huh/v2"
	"github.com/tinyauthapp/tinyauth/internal/utils/tlog"
	"github.com/tinyauthapp/paerser/cli"
	"golang.org/x/crypto/bcrypt"
)

type CreateUserConfig struct {
	Interactive bool   `description:"Create a user interactively."`
	Docker      bool   `description:"Format output for docker."`
	Username    string `description:"Username."`
	Password    string `description:"Password."`
}

func NewCreateUserConfig() *CreateUserConfig {
	return &CreateUserConfig{
		Interactive: false,
		Docker:      false,
		Username:    "",
		Password:    "",
	}
}

func createUserCmd() *cli.Command {
	tCfg := NewCreateUserConfig()

	loaders := []cli.ResourceLoader{
		&cli.FlagLoader{},
	}

	return &cli.Command{
		Name:          "create",
		Description:   "Create a user",
		Configuration: tCfg,
		Resources:     loaders,
		Run: func(_ []string) error {
			tlog.NewSimpleLogger().Init()

			if tCfg.Interactive {
				form := huh.NewForm(
					huh.NewGroup(
						huh.NewInput().Title("Username").Value(&tCfg.Username).Validate((func(s string) error {
							if s == "" {
								return errors.New("username cannot be empty")
							}
							return nil
						})),
						huh.NewInput().Title("Password").Value(&tCfg.Password).Validate((func(s string) error {
							if s == "" {
								return errors.New("password cannot be empty")
							}
							return nil
						})),
						huh.NewSelect[bool]().Title("Format the output for Docker?").Options(huh.NewOption("Yes", true), huh.NewOption("No", false)).Value(&tCfg.Docker),
					),
				)

				theme := new(themeBase)
				err := form.WithTheme(theme).Run()

				if err != nil {
					return fmt.Errorf("failed to run interactive prompt: %w", err)
				}
			}

			if tCfg.Username == "" || tCfg.Password == "" {
				return errors.New("username and password cannot be empty")
			}

			tlog.App.Info().Str("username", tCfg.Username).Msg("Creating user")

			passwd, err := bcrypt.GenerateFromPassword([]byte(tCfg.Password), bcrypt.DefaultCost)
			if err != nil {
				return fmt.Errorf("failed to hash password: %w", err)
			}

			// If docker format is enabled, escape the dollar sign
			passwdStr := string(passwd)
			if tCfg.Docker {
				passwdStr = strings.ReplaceAll(passwdStr, "$", "$$")
			}

			tlog.App.Info().Str("user", fmt.Sprintf("%s:%s", tCfg.Username, passwdStr)).Msg("User created")

			return nil
		},
	}
}
