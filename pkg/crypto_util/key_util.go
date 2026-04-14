package crypto_util

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

type KeyPair struct {
	PublicKey  string
	PrivateKey string
}

// GenerateKeyPair Generates an x25519 public, private key pair in 'der' format, encoded as base64
func GenerateKeyPair() (KeyPair, error) {
	// Generate X25519 private key
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Format private key to DER (PKCS#8)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return KeyPair{}, fmt.Errorf("failed to marshal private key: %w", err)
	}
	privateKeyString := base64.StdEncoding.EncodeToString(privateKeyBytes)

	// Format public key to DER (SPKI)
	publicKey := privateKey.PublicKey()
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return KeyPair{}, fmt.Errorf("failed to marshal public key: %w", err)
	}
	publicKeyString := base64.StdEncoding.EncodeToString(publicKeyBytes)

	return KeyPair{
		PublicKey:  publicKeyString,
		PrivateKey: privateKeyString,
	}, nil
}

// GenerateSharedKey Generates a shared key via X25519 diffie-hellman
func GenerateSharedKey(privateKeyString, publicKeyString string) (string, error) {
	// Decode private key — try standard encoding first, fall back to raw (no padding)
	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyString)
	if err != nil {
		privateKeyBytes, err = base64.RawStdEncoding.DecodeString(privateKeyString)
		if err != nil {
			return "", fmt.Errorf("failed to decode private key base64: %w", err)
		}
	}

	// Parse PKCS#8 private key
	parsedPriv, err := x509.ParsePKCS8PrivateKey(privateKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}
	ecdhPriv, ok := parsedPriv.(*ecdh.PrivateKey)
	if !ok {
		return "", fmt.Errorf("parsed private key is not of type *ecdh.PrivateKey")
	}

	// Decode public key — try standard encoding first, fall back to raw (no padding)
	// Registry may return keys without trailing = padding
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyString)
	if err != nil {
		publicKeyBytes, err = base64.RawStdEncoding.DecodeString(publicKeyString)
		if err != nil {
			return "", fmt.Errorf("failed to decode public key base64: %w", err)
		}
	}

	// Parse SPKI public key
	parsedPub, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse public key: %w", err)
	}
	ecdhPub, ok := parsedPub.(*ecdh.PublicKey)
	if !ok {
		return "", fmt.Errorf("parsed public key is not of type *ecdh.PublicKey")
	}

	// Generate shared secret
	sharedSecret, err := ecdhPriv.ECDH(ecdhPub)
	if err != nil {
		return "", fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Return base64 encoded shared key
	return base64.StdEncoding.EncodeToString(sharedSecret), nil
}
