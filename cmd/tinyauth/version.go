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
			fmt.Printf("Version: %s\n", model.Version)
			fmt.Printf("Commit Hash: %s\n", model.CommitHash)
			fmt.Printf("Build Timestamp: %s\n", model.BuildTimestamp)
			return nil
		},
	}
}
