package crypto_util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
)

type EncryptedPayload struct {
	EncryptedData string `json:"encrypted_data"`
	Hmac          string `json:"hmac"`
	Nonce         string `json:"nonce"`
}

// EncryptData Encrypts UTF-8 string by passing a shared key.
// Returns a base64-encoded JSON string containing encrypted_data, hmac, and nonce.
func EncryptData(sharedKey string, data string) (string, error) {
	sharedKeyBytes, err := base64.StdEncoding.DecodeString(sharedKey)
	if err != nil {
		return "", fmt.Errorf("invalid shared key encoding: %w", err)
	}

	block, err := aes.NewCipher(sharedKeyBytes)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, IVLengthInBytes)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCMWithNonceSize(block, IVLengthInBytes)
	if err != nil {
		return "", err
	}

	// Seal encrypts and authenticates plaintext, appending the auth tag to the ciphertext
	ciphertextAndTag := aesGCM.Seal(nil, nonce, []byte(data), nil)

	// Since NewGCM uses standard tag size (16 bytes = 128 bits), the tag is the last 16 bytes
	tagIndex := len(ciphertextAndTag) - AuthTagLengthInBytes
	ciphertext := ciphertextAndTag[:tagIndex]
	authTag := ciphertextAndTag[tagIndex:]

	// Construct payload base64 strings
	encryptedMessageBase64 := base64.StdEncoding.EncodeToString(ciphertext)
	authTagBase64 := base64.StdEncoding.EncodeToString(authTag)
	nonceBase64 := base64.StdEncoding.EncodeToString(nonce)

	// Build JSON
	payload := EncryptedPayload{
		EncryptedData: encryptedMessageBase64,
		Hmac:          authTagBase64,
		Nonce:         nonceBase64,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(payloadBytes), nil
}

// DecryptData Decrypts the AES-256-GCM encrypted data produced by EncryptData.
func DecryptData(sharedKey string, eData string) (string, error) {
	// Decode outer base64 payload
	payloadBytes, err := base64.StdEncoding.DecodeString(eData)
	if err != nil {
		return "", fmt.Errorf("invalid payload format: %w", err)
	}

	var payload EncryptedPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return "", fmt.Errorf("malformed payload json: %w", err)
	}

	sharedKeyBytes, err := base64.StdEncoding.DecodeString(sharedKey)
	if err != nil {
		return "", fmt.Errorf("invalid shared key encoding: %w", err)
	}

	nonceBytes, err := base64.StdEncoding.DecodeString(payload.Nonce)
	if err != nil {
		return "", err
	}

	encryptedDataBytes, err := base64.StdEncoding.DecodeString(payload.EncryptedData)
	if err != nil {
		return "", err
	}

	authTagBytes, err := base64.StdEncoding.DecodeString(payload.Hmac)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(sharedKeyBytes)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCMWithNonceSize(block, IVLengthInBytes)
	if err != nil {
		return "", err
	}

	// Reconstruct the full ciphertext+tag that aesGCM.Open expects
	ciphertextAndTag := append(encryptedDataBytes, authTagBytes...)

	plaintext, err := aesGCM.Open(nil, nonceBytes, ciphertextAndTag, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	return string(plaintext), nil
}
