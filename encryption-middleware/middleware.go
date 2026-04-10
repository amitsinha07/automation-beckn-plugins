package encryptionmiddleware

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	cryptoutil "github.com/ONDC-Official/automation-beckn-plugins/pkg/crypto_util"
	keymanager "github.com/ONDC-Official/automation-beckn-plugins/workbench-keymanager"
	"github.com/beckn-one/beckn-onix/pkg/log"
	"context"
)

// EncryptionMiddleware decrypts incoming encrypted payloads BEFORE signvalidator runs.
// The signvalidator then naturally validates the Authorization header against the
// decrypted plaintext JSON — no changes to signvalidator are needed.
type EncryptionMiddleware struct {
	keyMgr *keymanager.KeyMgr
}

// New creates the incoming decryption middleware.
// KeyMgr is instantiated internally using the same .env / viper environment
// as the keymanager plugin — no host injection needed.
func New(ctx context.Context) (func(http.Handler) http.Handler, error) {
	mgr, _, err := keymanager.New(ctx, nil, nil, &keymanager.Config{})
	if err != nil {
		return nil, fmt.Errorf("encryption-middleware: failed to init key manager: %w", err)
	}
	m := &EncryptionMiddleware{keyMgr: mgr}
	return m.handler, nil
}

func (m *EncryptionMiddleware) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			log.Errorf(ctx, err, "encryption-middleware: failed to read request body")
			http.Error(w, "failed to read request body", http.StatusInternalServerError)
			return
		}
		// Always restore body so downstream reads work regardless of path taken.
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		if !isEncryptedPayload(bodyBytes) {
			// Plain JSON — pass through unchanged to signvalidator
			next.ServeHTTP(w, r)
			return
		}

		log.Infof(ctx, "encryption-middleware: encrypted payload detected, decrypting before signvalidator")

		// 1. Parse Authorization header to identify the sender NP
		subscriberID, ukId, parseErr := parseAuthHeader(r.Header.Get("Authorization"))
		if parseErr != nil {
			log.Errorf(ctx, parseErr, "encryption-middleware: failed to parse Authorization header")
			http.Error(w, "invalid Authorization header", http.StatusBadRequest)
			return
		}

		// 2. Fetch sender's encryption public key from ONDC registry
		_, encrPubKey, lookupErr := m.keyMgr.LookupNPKeys(ctx, subscriberID, ukId)
		if lookupErr != nil {
			log.Errorf(ctx, lookupErr, "encryption-middleware: registry lookup failed for subscriber %s", subscriberID)
			http.Error(w, "failed to lookup NP encryption key", http.StatusInternalServerError)
			return
		}
		if encrPubKey == "" {
			log.Errorf(ctx, fmt.Errorf("empty encr_public_key for %s", subscriberID),
				"encryption-middleware: registry returned no encryption public key")
			http.Error(w, "NP encryption key not found in registry", http.StatusInternalServerError)
			return
		}

		// 3. Derive shared AES key: workbench EncrPrivate + sender's EncrPublic
		sharedKey, skErr := cryptoutil.GenerateSharedKey(m.keyMgr.GetEncrPrivateKey(), encrPubKey)
		if skErr != nil {
			log.Errorf(ctx, skErr, "encryption-middleware: failed to generate shared key")
			http.Error(w, "failed to generate shared key", http.StatusInternalServerError)
			return
		}

		// 4. Decrypt the payload
		decrypted, decErr := cryptoutil.DecryptData(sharedKey, strings.TrimSpace(string(bodyBytes)))
		if decErr != nil {
			log.Errorf(ctx, decErr, "encryption-middleware: decryption failed")
			http.Error(w, "failed to decrypt payload", http.StatusBadRequest)
			return
		}

		log.Infof(ctx, "encryption-middleware: decryption successful, forwarding plain JSON to signvalidator")
		log.Infof(ctx, "encryption-middleware: decrypted plaintext: %s", decrypted)

		// 5. Replace request body with decrypted plaintext JSON
		decryptedBytes := []byte(decrypted)
		r.Body = io.NopCloser(bytes.NewBuffer(decryptedBytes))
		r.ContentLength = int64(len(decryptedBytes))

		// Forward — signvalidator now sees plain JSON and validates Auth header against it
		next.ServeHTTP(w, r)
	})
}

// isEncryptedPayload returns true when the body is a base64 string whose decoded JSON
// contains the keys encrypted_data, hmac, and nonce — matching the EncryptedPayload struct.
func isEncryptedPayload(body []byte) bool {
	trimmed := strings.TrimSpace(string(body))
	if len(trimmed) == 0 {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		return false
	}
	var check map[string]any
	if err := json.Unmarshal(decoded, &check); err != nil {
		return false
	}
	_, hasData := check["encrypted_data"]
	_, hasHmac := check["hmac"]
	_, hasNonce := check["nonce"]
	return hasData && hasHmac && hasNonce
}

// parseAuthHeader extracts subscriber_id and ukId from the ONDC Authorization header.
// Header format: Signature keyId="{subscriber_id}|{unique_key_id}|{algo}",algorithm="...",...
func parseAuthHeader(authHeader string) (subscriberID, ukId string, err error) {
	if authHeader == "" {
		return "", "", fmt.Errorf("Authorization header is empty")
	}
	authHeader = strings.TrimPrefix(authHeader, "Signature ")
	parts := strings.Split(authHeader, ",")
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		if strings.TrimSpace(kv[0]) == "keyId" {
			// Value is wrapped in quotes: "subscriber_id|ukid|algo"
			keyIdValue := strings.Trim(kv[1], "\"")
			segments := strings.SplitN(keyIdValue, "|", 3)
			if len(segments) < 2 {
				return "", "", fmt.Errorf("malformed keyId in Authorization header: %s", keyIdValue)
			}
			return segments[0], segments[1], nil
		}
	}
	return "", "", fmt.Errorf("keyId not found in Authorization header")
}
