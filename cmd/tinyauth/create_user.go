package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"charm.land/huh/v2"
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

	cmd := &cli.Command{
		Name:          "create",
		Description:   "Create a user",
		Configuration: tCfg,
		Resources:     loaders,
	}

	cmd.Run = func(_ []string) error {
		if tCfg.Interactive {
			form := huh.NewForm(
				huh.NewGroup(
					huh.NewInput().Title("Username").Value(&tCfg.Username).Validate(func(s string) error {
						if s == "" {
							return errors.New("username cannot be empty")
						}
						if strings.Contains(s, ":") {
							return errors.New("username cannot contain ':'")
						}
						return nil
					}),
					huh.NewInput().Title("Password").Value(&tCfg.Password).Validate(func(s string) error {
						if s == "" {
							return errors.New("password cannot be empty")
						}
						return nil
					}),
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
			cmd.PrintHelp(os.Stdout)
			return errors.New("username and password cannot be empty")
		}

		if strings.Contains(tCfg.Username, ":") {
			return errors.New("username cannot contain ':'")
		}

		passwd, err := bcrypt.GenerateFromPassword([]byte(tCfg.Password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}

		// Only the docker compose output needs $ escaped, the raw hash is correct everywhere else
		passwdStr := string(passwd)
		outputStr := passwdStr

		if tCfg.Docker {
			outputStr = strings.ReplaceAll(passwdStr, "$", "$$")
		}

		user := fmt.Sprintf("%s:%s", tCfg.Username, passwdStr)
		escapedUser := fmt.Sprintf("%s:%s", tCfg.Username, outputStr)
		escapedUser = `"` + escapedUser + `"`

		buf := strings.Builder{}

		// header
		fmt.Fprintf(&buf, "Created user '%s'.\n\n", tCfg.Username)

		// environment variable
		fmt.Fprint(&buf, "Environment variable:\n\n")
		renderToBuf(&buf, []kv{
			{"TINYAUTH_AUTH_USERS", escapedUser},
		}, "=")

		// cli flags
		fmt.Fprint(&buf, "\nCLI flags:\n\n")
		renderToBuf(&buf, []kv{
			{"--auth.users", escapedUser},
		}, "=")

		// yaml config
		fmt.Fprint(&buf, "\nYAML config:\n\n")

		buf.WriteString(redStyle.Render("auth"))
		buf.WriteString(grayStyle.Render(":"))
		buf.WriteString("\n")
		buf.WriteString(redStyle.Render("  users"))
		buf.WriteString(grayStyle.Render(":"))
		buf.WriteString(" ")
		buf.WriteString(greenStyle.Render(user))
		buf.WriteString("\n\n")

		// footer
		fmt.Fprint(&buf, "Use your config option of choice to add the user to Tinyauth and then restart.")

		fmt.Println(buf.String())
		return nil
	}

	return cmd
}
