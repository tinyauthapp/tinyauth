package main

import (
	"fmt"

	"github.com/tinyauthapp/tinyauth/internal/config"

	"github.com/tinyauthapp/paerser/cli"
)

func versionCmd() *cli.Command {
	return &cli.Command{
		Name:          "version",
		Description:   "Print the version number of Tinyauth",
		Configuration: nil,
		Resources:     nil,
		Run: func(_ []string) error {
			fmt.Printf("Version: %s\n", config.Version)
			fmt.Printf("Commit Hash: %s\n", config.CommitHash)
			fmt.Printf("Build Timestamp: %s\n", config.BuildTimestamp)
			return nil
		},
	}
}
