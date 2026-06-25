package signvalidator

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/beckn-one/beckn-onix/pkg/model"
	"golang.org/x/crypto/blake2b"
)

// Config struct for Verifier.
type Config struct {
}

// validator implements the validator interface.
type validator struct {
	config *Config
}

// New creates a new Verifier instance.
func New(ctx context.Context, config *Config) (*validator, func() error, error) {
	v := &validator{config: config}

	return v, nil, nil
}

// Verify checks the signature for the given payload and public key.
func (v *validator) Validate(ctx context.Context, body []byte, header string, publicKeyBase64 string) error {
	createdTimestamp, expiredTimestamp, signature, err := parseAuthHeader(header)
	if err != nil {
		return model.NewSignValidationErr(fmt.Errorf("error parsing header: %w", err))
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return model.NewSignValidationErr(fmt.Errorf("error decoding signature: %w", err))
	}

	currentTime := time.Now().Unix()
	if createdTimestamp > currentTime || currentTime > expiredTimestamp {
		return model.NewSignValidationErr(fmt.Errorf("signature is expired or not yet valid"))
	}

	decodedPublicKey, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return model.NewSignValidationErr(fmt.Errorf("error decoding public key: %w", err))
	}
	if len(decodedPublicKey) != ed25519.PublicKeySize {
		return model.NewSignValidationErr(fmt.Errorf("invalid public key length: %d", len(decodedPublicKey)))
	}

	// Primary path: the sender stringified the body before signing (correct
	// usage). Verify the signature against the actual request body.
	if verifySignature(decodedPublicKey, body, createdTimestamp, expiredTimestamp, signatureBytes) {
		return nil
	}

	// Fallback: some senders do NOT stringify the body before signing. In
	// Node.js, passing an object to sodium.from_string coerces it to the literal
	// string "[object Object]", so the digest is computed over that constant
	// instead of the JSON body. Accept such headers by verifying against the same
	// constant.
	//
	// WARNING: requests accepted via this fallback are NOT integrity-protected —
	// the signature does not cover the actual body content. This exists only to
	// interoperate with a known-broken signer; remove it once the signer is fixed
	// to sign JSON.stringify(body).
	if verifySignature(decodedPublicKey, []byte(objectObjectLiteral), createdTimestamp, expiredTimestamp, signatureBytes) {
		fmt.Printf("WARN signvalidator: signature verified via [object Object] fallback; request body integrity NOT verified\n")
		return nil
	}

	return model.NewSignValidationErr(fmt.Errorf("signature verification failed"))
}

// objectObjectLiteral is the JavaScript string coercion of a non-stringified
// object (String({}) === "[object Object]"). A sender that signs an object
// instead of JSON.stringify(object) ends up signing the digest of this constant.
const objectObjectLiteral = "[object Object]"

// verifySignature reconstructs the signing string for the given payload and
// checks the Ed25519 signature against it.
func verifySignature(publicKey ed25519.PublicKey, payload []byte, created, expired int64, signature []byte) bool {
	signingString := hash(payload, created, expired)
	return ed25519.Verify(publicKey, []byte(signingString), signature)
}

// parseAuthHeader extracts signature values from the Authorization header.
func parseAuthHeader(header string) (int64, int64, string, error) {
	header = strings.TrimPrefix(header, "Signature ")

	parts := strings.Split(header, ",")
	signatureMap := make(map[string]string)

	for _, part := range parts {
		keyValue := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(keyValue) == 2 {
			key := strings.TrimSpace(keyValue[0])
			value := strings.Trim(keyValue[1], "\"")
			signatureMap[key] = value
		}
	}

	createdTimestamp, err := strconv.ParseInt(signatureMap["created"], 10, 64)
	if err != nil {
		// TODO: Return appropriate error code when Error Code Handling Module is ready
		return 0, 0, "", fmt.Errorf("invalid created timestamp: %w", err)
	}

	expiredTimestamp, err := strconv.ParseInt(signatureMap["expires"], 10, 64)
	if err != nil {
		return 0, 0, "", model.NewSignValidationErr(fmt.Errorf("invalid expires timestamp: %w", err))
	}

	signature := signatureMap["signature"]
	if signature == "" {
		// TODO: Return appropriate error code when Error Code Handling Module is ready
		return 0, 0, "", model.NewSignValidationErr(fmt.Errorf("signature missing in header"))
	}

	return createdTimestamp, expiredTimestamp, signature, nil
}

// hash constructs a signing string for verification.
func hash(payload []byte, createdTimestamp, expiredTimestamp int64) string {
	hasher, _ := blake2b.New512(nil)
	hasher.Write(payload)
	hashSum := hasher.Sum(nil)
	digestB64 := base64.StdEncoding.EncodeToString(hashSum)

	return fmt.Sprintf("(created): %d\n(expires): %d\ndigest: BLAKE-512=%s", createdTimestamp, expiredTimestamp, digestB64)
}
