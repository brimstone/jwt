package cobra

import (
	"fmt"
	"os"

	"github.com/brimstone/jwt/jwt"
	"github.com/spf13/cobra"
)

var GenTokenCmd = &cobra.Command{
	Use:   "gentoken <payload>",
	Short: "Generates a token, signed by a key.",
	Long: `Generates a token signed by either an HMAC or RSA key.
Use genhmac or genrsa to generate these keys.
Payload must be a valid JSON object
`,
	Run: GenToken,
}

func init() {
	GenTokenCmd.Flags().StringP("key", "k", "", "The secret key used to sign the token.")
}

func GenToken(cmd *cobra.Command, args []string) {
	key, _ := cmd.Flags().GetString("key")
	if key == "" {
		fmt.Fprintf(os.Stderr, "Must specfy a key with -k\n")
		os.Exit(1)
	}
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Must specify a payload to sign as arguments")
		os.Exit(1)
	}

	token, err := jwt.GenToken(key, []byte(args[0]))
	if err != nil {
		panic(err)
	}
	fmt.Println(token)
}
