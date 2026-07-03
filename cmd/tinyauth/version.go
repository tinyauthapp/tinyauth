package main

import (
	"fmt"

	"github.com/tinyauthapp/paerser/cli"
	"github.com/tinyauthapp/tinyauth/internal/model"
)

func versionCmd() *cli.Command {
	return &cli.Command{
		Name:          "version",
		Description:   "Print the version number of Tinyauth",
		Configuration: nil,
		Resources:     nil,
		Run: func(_ []string) error {
			colors := getColors()
			fmt.Printf("Version: %s\n", colors.blue.Render(model.Version))
			fmt.Printf("Commit Hash: %s\n", colors.blue.Render(model.CommitHash))
			fmt.Printf("Build Timestamp: %s\n", colors.blue.Render(model.BuildTimestamp))
			return nil
		},
	}
}
