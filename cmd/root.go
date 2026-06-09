package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "vscan",
	Short: "A fast port scanner written in Go",
	Long: `vscan is a high-performance port scanner supporting:
  - TCP Connect scanning
  - SYN half-open scanning (requires root)
  - CIDR range expansion
  - Service detection and banner grabbing
  - Multiple output formats (CLI, JSON, CSV)`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
