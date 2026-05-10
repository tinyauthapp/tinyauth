package main

import (
	"errors"
	"fmt"

	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"

	"charm.land/huh/v2"
	"github.com/pquerna/otp/totp"
	"github.com/tinyauthapp/paerser/cli"
	"golang.org/x/crypto/bcrypt"
)

type VerifyUserConfig struct {
	Interactive bool   `description:"Validate a user interactively."`
	Username    string `description:"Username."`
	Password    string `description:"Password."`
	Totp        string `description:"TOTP code."`
	User        string `description:"Hash (username:hash:totp)."`
}

func NewVerifyUserConfig() *VerifyUserConfig {
	return &VerifyUserConfig{
		Interactive: false,
		Username:    "",
		Password:    "",
		Totp:        "",
		User:        "",
	}
}

func verifyUserCmd() *cli.Command {
	tCfg := NewVerifyUserConfig()

	loaders := []cli.ResourceLoader{
		&cli.FlagLoader{},
	}

	return &cli.Command{
		Name:          "verify",
		Description:   "Verify a user is set up correctly",
		Configuration: tCfg,
		Resources:     loaders,
		Run: func(_ []string) error {
			log := logger.NewLogger().WithSimpleConfig()
			log.Init()

			if tCfg.Interactive {
				form := huh.NewForm(
					huh.NewGroup(
						huh.NewInput().Title("User (username:hash:totp)").Value(&tCfg.User).Validate((func(s string) error {
							if s == "" {
								return errors.New("user cannot be empty")
							}
							return nil
						})),
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
						huh.NewInput().Title("TOTP Code (optional)").Value(&tCfg.Totp),
					),
				)

				theme := new(themeBase)
				err := form.WithTheme(theme).Run()

				if err != nil {
					return fmt.Errorf("failed to run interactive prompt: %w", err)
				}
			}

			user, err := utils.ParseUser(tCfg.User)

			if err != nil {
				return fmt.Errorf("failed to parse user: %w", err)
			}

			if user.Username != tCfg.Username {
				return fmt.Errorf("username is incorrect")
			}

			err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(tCfg.Password))

			if err != nil {
				return fmt.Errorf("password is incorrect: %w", err)
			}

			if user.TOTPSecret == "" {
				if tCfg.Totp != "" {
					log.App.Warn().Msg("User does not have TOTP secret")
				}
				log.App.Info().Msg("User verified")
				return nil
			}

			ok := totp.Validate(tCfg.Totp, user.TOTPSecret)

			if !ok {
				return fmt.Errorf("TOTP code incorrect")
			}

			log.App.Info().Msg("User verified")

			return nil
		},
	}
}
