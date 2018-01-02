package cmd

import (
	"github.com/brimstone/jwt/cobra"
)

func init() {
	rootCmd.AddCommand(cobra.GenRSACmd)
}
