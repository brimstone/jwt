package cobra

import (
	"fmt"

	"github.com/brimstone/jwt/jwt"
	"github.com/spf13/cobra"
)

var GenHMACKeyCmd = &cobra.Command{
	Use:   "genhmac",
	Short: "Generates a key suitable for HMAC-SHA-256",
	Long: `genhmac generates a random key 512 bytes long, the block size of
SHA256, then base64 encodes it. This is sutable for use as the jwt key for
serve and gentoken.`,
	Run: GenHMACKey,
}

func GenHMACKey(cmd *cobra.Command, args []string) {
	fmt.Printf("%s\n", jwt.GenHMACKey())
}
