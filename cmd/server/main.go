package main

import (
	"github.com/hysp/hycert-api/internal/app"
	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:   "hycert-api",
		Short: "HySP Certificate Lifecycle Management API",
	}
	root.AddCommand(serveCmd())
	_ = root.Execute()
}

func serveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Start the API server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.Run()
		},
	}
}
