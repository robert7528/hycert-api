package main

import (
	"github.com/hysp/hycert-api/internal/app"
	"github.com/spf13/cobra"
)

func serveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Start the API server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.Run()
		},
	}
}
