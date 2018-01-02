package cobra

import (
	"fmt"
	"io/ioutil"

	"github.com/brimstone/jwt/jwt"
	"github.com/spf13/cobra"
)

var GenRSACmd = &cobra.Command{
	Use:   "genrsa",
	Short: "Generates a key suitable for RSA",
	Long: `genrsa generates a random key 2048 bits long, the block size of
SHA256, then base64 encodes it. This is sutable for use as the jwt key for
serve and gentoken.`,
	Run: GenRSA,
}

func init() {
	GenRSACmd.Flags().StringP("secret", "s", "", "The path to save the secret private key.")
	GenRSACmd.Flags().StringP("public", "p", "", "The path to save the public key.")
}

func GenRSA(cmd *cobra.Command, args []string) {
	private, public, err := jwt.GenRSAKey()
	if err != nil {
		panic(err)
	}
	// Save keys to a file
	secret, _ := cmd.Flags().GetString("secret")
	if secret == "" {
		fmt.Printf("%s", private)
	} else {
		err = ioutil.WriteFile(secret, []byte(private), 0600)
		if err != nil {
			panic(err)
		}
	}

	cert, _ := cmd.Flags().GetString("public")
	if cert == "" {
		fmt.Printf("%s", public)
	} else {
		err = ioutil.WriteFile(cert, []byte(public), 0644)
		if err != nil {
			panic(err)
		}
	}
}
