package jwt

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	jose "gopkg.in/square/go-jose.v2"
)

type payload struct {
	NBF int64 `json:"nbf"`
	EXP int64 `json:"exp"`
}

func Verify(key string, token string, receiver interface{}) error {
	obj, err := jose.ParseSigned(token)
	if err != nil {
		return fmt.Errorf("brimstone/jwt: parsing token: %s", err)
	}

	var public interface{}
	// if key is a valid file path to a RSA public key, try to load that
	keyBytes, err := ioutil.ReadFile(key)
	if err == nil {
		// Successful read from file
		block, _ := pem.Decode(keyBytes)

		if block == nil || block.Type != "PUBLIC KEY" {
			return fmt.Errorf("brimstone/jwt: failed to decode PEM block containing public key")
		}

		public, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("brimstone/jwt: unable to decode public key: %s", err)
		}
	} else {
		// Try to decode the key
		public, err = base64.StdEncoding.DecodeString(key)
		if err != nil {
			return fmt.Errorf("brimstone/jwt: unable to decode token: %s", err)
		}
	}

	plaintext, err := obj.Verify(public)
	if err != nil {
		return fmt.Errorf("brimstone/jwt: unable to verify token: %s", err)
	}

	var payloadStruct payload
	err = json.Unmarshal(plaintext, &payloadStruct)
	if err != nil {
		return fmt.Errorf("brimstone/jwt: unable to convert token to json: %s", err)
	}

	now := time.Now()
	nbf := time.Unix(payloadStruct.NBF, 0)
	if now.Before(nbf) {
		return fmt.Errorf("brimstone/jwt: token isn't valid until: %s", nbf)
	}
	exp := time.Unix(payloadStruct.EXP, 0)
	if now.After(exp) {
		return fmt.Errorf("brimstone/jwt: token isn't valid after: %s", exp)
	}

	err = json.Unmarshal(plaintext, receiver)
	if err != nil {
		return fmt.Errorf("brimstone/jwt: unable to convert token to json: %s", err)
	}
	return nil
}

func VerifyBearer(key string, r *http.Request, receiver interface{}) error {
	bearer := strings.Split(r.Header.Get("Authorization"), " ")
	if len(bearer) != 2 || bearer[0] != "Bearer" {
		return errors.New("Invalid Auth")
	}

	return Verify(key, bearer[1], receiver)
}
