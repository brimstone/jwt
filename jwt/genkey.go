package jwt

import (
	"crypto/rand"
	"encoding/base64"
)

func GenHMACKey() string {
	key := make([]byte, 512/8)
	rand.Read(key)
	return base64.StdEncoding.EncodeToString(key)
}
