package jwt

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"time"

	jose "gopkg.in/square/go-jose.v2"
)

func GenToken(key string, payload []byte) (string, error) {
	var signer jose.Signer
	// Setup signer
	keyBytes, err := ioutil.ReadFile(key)
	if err == nil {
		// Successful read from file
		block, _ := pem.Decode(keyBytes)

		if block == nil || block.Type != "RSA PRIVATE KEY" {
			return "", fmt.Errorf("failed to decode PEM block containing public key")
		}

		private, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return "", err
		}

		signer, err = jose.NewSigner(
			jose.SigningKey{Algorithm: jose.RS256, Key: private},
			&jose.SignerOptions{ExtraHeaders: map[jose.HeaderKey]interface{}{
				"typ": "JWT",
			}},
		)
		if err != nil {
			return "", err
		}
		// Must be an hmac key
	} else {
		secret, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			return "", err
		}

		signer, err = jose.NewSigner(
			jose.SigningKey{Algorithm: jose.HS256, Key: secret},
			&jose.SignerOptions{ExtraHeaders: map[jose.HeaderKey]interface{}{
				"typ": "JWT",
			}},
		)
		if err != nil {
			return "", err
		}
	}

	// convert bytes from user to a a map
	var payloadMap map[string]interface{}
	err = json.Unmarshal(payload, &payloadMap)
	if err != nil {
		return "", err
	}
	// Add things like iat, exp: https://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#rfc.section.4.1
	now := time.Now()
	if _, ok := payloadMap["iat"]; !ok {
		payloadMap["iat"] = now.Unix()
	}
	if _, ok := payloadMap["nbf"]; !ok {
		payloadMap["nbf"] = now.Unix()
	}
	// TODO allow user to set exp time
	if _, ok := payloadMap["exp"]; !ok {
		payloadMap["exp"] = now.Add(time.Hour * 24 * 365).Unix()
	}
	// convert map back to bytes
	marshalled, err := json.Marshal(payloadMap)
	if err != nil {
		return "", err
	}

	// TODO read from stdin if payload is empty
	// TODO if payload isn't already bytes, try to make it bytes
	obj, err := signer.Sign(marshalled)
	if err != nil {
		return "", err
	}
	token, err := obj.CompactSerialize()
	//token := obj.FullSerialize()
	if err != nil {
		return "", err
	}
	return token, nil

}
