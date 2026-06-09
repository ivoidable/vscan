package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("vscan v1.0.0")
		fmt.Println("A fast port scanner written in Go")
		fmt.Println("https://github.com/ivoidable/vscan")
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
