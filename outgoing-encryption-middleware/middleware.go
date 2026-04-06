package outgoingencryptionmiddleware

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	cryptoutil "github.com/ONDC-Official/automation-beckn-plugins/pkg/crypto_util"
	keymanager "github.com/ONDC-Official/automation-beckn-plugins/workbench-keymanager"
	"github.com/beckn-one/beckn-onix/pkg/log"
)

// OutgoingEncryptionMiddleware encrypts the request body AFTER the Signer plugin
// has already signed the plaintext and set the Authorization header.
//
// Flow in the plugin chain (Caller / outgoing direction):
//   WorkbenchReceiver → Signer (signs plaintext, sets Auth header)
//   → OutgoingEncryptionMiddleware (encrypts body, Auth header untouched)
//   → Router (sends encrypted body to external NP)
//
// The external NP receives:
//   - Body: AES-256-GCM ciphertext (base64 encoded EncryptedPayload JSON)
//   - Authorization header: signed over the original plaintext JSON
//
// External NP verification:
//   1. Decrypt body → get plaintext JSON
//   2. Verify Authorization header against the decrypted plaintext ✓
type OutgoingEncryptionMiddleware struct {
	keyMgr *keymanager.KeyMgr
}

// New creates the post-signer outgoing encryption middleware.
// KeyMgr is instantiated internally using the same .env / viper environment
// as the keymanager plugin — no host injection needed.
func New(ctx context.Context) (func(http.Handler) http.Handler, error) {
	mgr, _, err := keymanager.New(ctx, nil, nil, &keymanager.Config{})
	if err != nil {
		return nil, fmt.Errorf("outgoing-encryption-middleware: failed to init key manager: %w", err)
	}
	m := &OutgoingEncryptionMiddleware{keyMgr: mgr}
	return m.handler, nil
}

func (m *OutgoingEncryptionMiddleware) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Check the encryption_validation cookie set by WorkbenchReceiver (utils.go).
		// This cookie reflects the session's EncryptionValidation difficulty flag.
		encValidationCookie, cookieErr := r.Cookie("encryption_validation")
		if cookieErr != nil || encValidationCookie.Value != "true" {
			// Encryption not required — forward unchanged to Router
			next.ServeHTTP(w, r)
			return
		}

		log.Infof(ctx, "outgoing-encryption-middleware: encryption_validation=true, encrypting body after signing")

		// Read subscriber_id cookie — set by WorkbenchReceiver in setRequestCookies.
		// In Caller mode this is the counterparty NP (bpp_id for BAP, bap_id for BPP).
		subscriberCookie, subErr := r.Cookie("subscriber_id")
		if subErr != nil || strings.TrimSpace(subscriberCookie.Value) == "" {
			log.Errorf(ctx, fmt.Errorf("subscriber_id cookie missing or empty"),
				"outgoing-encryption-middleware: cannot determine target NP subscriber ID")
			http.Error(w, "subscriber_id cookie missing for outgoing encryption", http.StatusInternalServerError)
			return
		}
		subscriberID := subscriberCookie.Value

		// Read the body — at this point the Signer has already:
		//   1. Read the plaintext body
		//   2. Computed the Auth header over the plaintext
		//   3. Written the Auth header to r.Header["Authorization"]
		// The body bytes are still the plaintext JSON.
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			log.Errorf(ctx, err, "outgoing-encryption-middleware: failed to read body")
			http.Error(w, "failed to read request body", http.StatusInternalServerError)
			return
		}

		// 1. Fetch target NP's encryption public key from ONDC registry.
		// Empty ukId — registry returns the full NP record which includes encr_public_key.
		_, encrPubKey, lookupErr := m.keyMgr.LookupNPKeys(ctx, subscriberID, "")
		if lookupErr != nil {
			log.Errorf(ctx, lookupErr,
				"outgoing-encryption-middleware: registry lookup failed for %s", subscriberID)
			http.Error(w, "failed to lookup target NP encryption key", http.StatusInternalServerError)
			return
		}
		if encrPubKey == "" {
			log.Errorf(ctx, fmt.Errorf("empty encr_public_key for %s", subscriberID),
				"outgoing-encryption-middleware: target NP has no encryption key in registry")
			http.Error(w, "target NP encryption key not found in registry", http.StatusInternalServerError)
			return
		}

		// 2. Derive shared AES key: workbench EncrPrivate + target NP's EncrPublic
		sharedKey, skErr := cryptoutil.GenerateSharedKey(m.keyMgr.GetEncrPrivateKey(), encrPubKey)
		if skErr != nil {
			log.Errorf(ctx, skErr, "outgoing-encryption-middleware: failed to generate shared key")
			http.Error(w, "failed to generate shared key", http.StatusInternalServerError)
			return
		}

		// 3. Encrypt the signed plaintext body.
		// IMPORTANT: The Authorization header is NOT modified here.
		// The external NP must decrypt the body first, then verify the Auth header
		// against the decrypted plaintext.
		encryptedString, encErr := cryptoutil.EncryptData(sharedKey, string(bodyBytes))
		if encErr != nil {
			log.Errorf(ctx, encErr, "outgoing-encryption-middleware: encryption failed")
			http.Error(w, "failed to encrypt outgoing payload", http.StatusInternalServerError)
			return
		}

		encryptedBytes := []byte(encryptedString)
		r.Body = io.NopCloser(bytes.NewBuffer(encryptedBytes))
		r.ContentLength = int64(len(encryptedBytes))

		log.Infof(ctx, "outgoing-encryption-middleware: body encrypted (%d bytes), Auth header preserved; forwarding to router",
			len(encryptedBytes))

		// Forward to Router — sends encrypted body with Auth header signed over plaintext
		next.ServeHTTP(w, r)
	})
}
