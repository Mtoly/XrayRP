package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Mtoly/XrayRP/internal/buildinfo"
)

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print current version of XrayR",
		Run: func(cmd *cobra.Command, args []string) {
			showVersion()
		},
	})
}

func showVersion() {
	fmt.Print(buildinfo.Current().String())
}
