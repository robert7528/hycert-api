package main

import (
	"log"

	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:   "hycert",
		Short: "HySP Certificate Lifecycle Management",
	}

	root.AddCommand(
		serveCmd(),
		migrateCmd(),
		certCmd(),
	)

	if err := root.Execute(); err != nil {
		log.Fatal(err)
	}
}
