package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func GenRSAKey() (string, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("brimstone/jwt: unable to generate private key: %s", err)
	}

	privateblock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	public, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return "", "", fmt.Errorf("brimstone/jwt: unable to generate public key: %s", err)
	}
	publicblock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: public,
	}

	return string(pem.EncodeToMemory(privateblock)), string(pem.EncodeToMemory(publicblock)), nil
}
