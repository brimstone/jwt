package cobra

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/brimstone/jwt/jwt"
	"github.com/spf13/cobra"
)

var VerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: Verify,
}

func init() {
	VerifyCmd.Flags().StringP("key", "k", "", "The secret key used to sign the token.")
	VerifyCmd.Flags().StringP("token", "t", "", "The token.")
}

func Verify(cmd *cobra.Command, args []string) {
	key, _ := cmd.Flags().GetString("key")
	if key == "" {
		fmt.Fprintf(os.Stderr, "Must specfy a key with -k\n")
		os.Exit(1)
	}
	token, _ := cmd.Flags().GetString("token")
	if token == "" {
		fmt.Fprintf(os.Stderr, "Must specfy a token with -t\n")
		os.Exit(1)
	}
	var payload map[string]interface{}
	err := jwt.Verify(key, token, &payload)
	if err != nil {
		panic(err)
	}

	marshalled, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", marshalled)
}
