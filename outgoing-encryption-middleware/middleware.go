package outgoingencryptionmiddleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	cryptoutil "github.com/ONDC-Official/automation-beckn-plugins/pkg/crypto_util"
	keymanager "github.com/ONDC-Official/automation-beckn-plugins/workbench-keymanager"
	"github.com/beckn-one/beckn-onix/pkg/log"
)

// OutgoingEncryptionTransport encrypts the outgoing request body AFTER the Signer plugin
// has already signed the plaintext and set the Authorization header.
//
// It implements http.RoundTripper (TransportWrapper pattern) so it runs at the very last
// moment — after ALL pipeline steps (including `sign`) have executed and
// all session cookies (including encryption_validation) are set on the request.
//
// Flow in the plugin chain (Caller / outgoing direction):
//
//	ondcWorkbenchReceiver (sets cookies) → sign (sets Auth header)
//	  → [http.Client.Do] → TransportWrapper.RoundTrip
//	     → OutgoingEncryptionTransport (encrypts body) → base.RoundTrip → external NP
//
// The external NP receives:
//   - Body: AES-256-GCM ciphertext (base64 encoded EncryptedPayload JSON)
//   - Authorization header: signed over the original plaintext JSON
//
// External NP verification:
//  1. Decrypt body → get plaintext JSON
//  2. Verify Authorization header against the decrypted plaintext ✓
type OutgoingEncryptionTransport struct {
	base   http.RoundTripper
	keyMgr *keymanager.KeyMgr
}

// OutgoingEncryptionWrapper implements definition.TransportWrapper.
type OutgoingEncryptionWrapper struct {
	keyMgr *keymanager.KeyMgr
}

// New creates the outgoing encryption transport wrapper.
func New(ctx context.Context) (*OutgoingEncryptionWrapper, func(), error) {
	mgr, _, err := keymanager.New(ctx, nil, nil, &keymanager.Config{})
	if err != nil {
		return nil, nil, fmt.Errorf("outgoing-encryption-middleware: failed to init key manager: %w", err)
	}
	return &OutgoingEncryptionWrapper{keyMgr: mgr}, nil, nil
}

// Wrap implements definition.TransportWrapper.
func (w *OutgoingEncryptionWrapper) Wrap(base http.RoundTripper) http.RoundTripper {
	return &OutgoingEncryptionTransport{
		base:   base,
		keyMgr: w.keyMgr,
	}
}

// becknContext is used to extract domain and subscriber info from the outgoing ONDC payload.
type becknContext struct {
	Context struct {
		Domain string `json:"domain"`
		BppID  string `json:"bpp_id"`
		BapID  string `json:"bap_id"`
	} `json:"context"`
}

// RoundTrip intercepts the outbound HTTP call, encrypts the body if required, then delegates.
func (t *OutgoingEncryptionTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// Log all cookies present in the request for debugging difficulty flags.
	// At this point (TransportWrapper), all pipeline steps have run and cookies are set.
	allCookies := req.Cookies()
	if len(allCookies) == 0 {
		log.Infof(ctx, "outgoing-encryption-middleware: no cookies present in request")
	} else {
		for _, c := range allCookies {
			log.Infof(ctx, "outgoing-encryption-middleware: cookie [%s] = [%s]", c.Name, c.Value)
		}
	}

	// Check the encryption_validation cookie — set by WorkbenchReceiver (utils.go).
	encValidationCookie, cookieErr := req.Cookie("encryption_validation")
	if cookieErr != nil {
		log.Infof(ctx, "outgoing-encryption-middleware: encryption_validation cookie missing or error: %v — skipping encryption", cookieErr)
		return t.base.RoundTrip(req)
	}
	log.Infof(ctx, "outgoing-encryption-middleware: encryption_validation cookie value: %s", encValidationCookie.Value)

	if encValidationCookie.Value != "true" {
		return t.base.RoundTrip(req)
	}

	log.Infof(ctx, "outgoing-encryption-middleware: encryption_validation=true, encrypting body after signing")

	// Read the body — at this point the Signer has already signed the plaintext body
	// and written the Authorization header. The body is still the plaintext JSON.
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		log.Errorf(ctx, err, "outgoing-encryption-middleware: failed to read body")
		return nil, fmt.Errorf("outgoing-encryption-middleware: failed to read request body: %w", err)
	}
	// Restore body so base transport can re-read if needed (will be replaced below).
	req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// Extract context.domain and target NP subscriber ID from the outgoing ONDC payload body.
	// For outgoing encryption we need the RECEIVER's encr_public_key, not our own.
	// The receiver is context.bpp_id (when caller is BAP sending to BPP).
	var payload becknContext
	if jsonErr := json.Unmarshal(bodyBytes, &payload); jsonErr != nil {
		log.Errorf(ctx, jsonErr, "outgoing-encryption-middleware: failed to parse request body for domain")
		return nil, fmt.Errorf("outgoing-encryption-middleware: failed to parse request body: %w", jsonErr)
	}
	domain := strings.TrimSpace(payload.Context.Domain)
	if domain == "" {
		log.Errorf(ctx, fmt.Errorf("context.domain is empty in request body"),
			"outgoing-encryption-middleware: cannot determine domain for registry lookup")
		return nil, fmt.Errorf("outgoing-encryption-middleware: context.domain is empty in request body")
	}

	// Use bpp_id as the target subscriber ID (mockTxnCaller is BAP, sends to BPP).
	// Fall back to bap_id if bpp_id is not present (e.g. reverse direction).
	subscriberID := strings.TrimSpace(payload.Context.BppID)
	if subscriberID == "" {
		subscriberID = strings.TrimSpace(payload.Context.BapID)
	}
	if subscriberID == "" {
		// Last resort: use subscriber_id cookie (our own ID)
		subscriberCookie, subErr := req.Cookie("subscriber_id")
		if subErr != nil || strings.TrimSpace(subscriberCookie.Value) == "" {
			return nil, fmt.Errorf("outgoing-encryption-middleware: cannot determine target NP subscriber ID (bpp_id/bap_id empty and no cookie)")
		}
		subscriberID = subscriberCookie.Value
		log.Infof(ctx, "outgoing-encryption-middleware: bpp_id/bap_id not in body, falling back to cookie subscriber_id=%s", subscriberID)
	}
	log.Infof(ctx, "outgoing-encryption-middleware: using subscriber_id=%s (target NP) domain=%s for registry lookup", subscriberID, domain)

	// 1. Fetch target NP's encryption public key from ONDC registry using domain lookup.
	signPubKey, encrPubKey, lookupErr := t.keyMgr.LookupNPKeysByDomain(ctx, subscriberID, domain)
	if lookupErr != nil {
		log.Errorf(ctx, lookupErr,
			"outgoing-encryption-middleware: registry lookup failed for %s", subscriberID)
		return nil, fmt.Errorf("outgoing-encryption-middleware: registry lookup failed for %s: %w", subscriberID, lookupErr)
	}
	log.Infof(ctx, "outgoing-encryption-middleware: retrieved sign public key from lookup: %s", signPubKey)
	log.Infof(ctx, "outgoing-encryption-middleware: retrieved encryption public key from lookup: %s", encrPubKey)

	if encrPubKey == "" {
		log.Errorf(ctx, fmt.Errorf("empty encr_public_key for %s", subscriberID),
			"outgoing-encryption-middleware: target NP has no encryption key in registry")
		return nil, fmt.Errorf("outgoing-encryption-middleware: target NP encryption key not found in registry for %s", subscriberID)
	}

	// 2. Derive shared AES key: workbench EncrPrivate + target NP's EncrPublic
	sharedKey, skErr := cryptoutil.GenerateSharedKey(t.keyMgr.GetEncrPrivateKey(), encrPubKey)
	if skErr != nil {
		log.Errorf(ctx, skErr, "outgoing-encryption-middleware: failed to generate shared key")
		return nil, fmt.Errorf("outgoing-encryption-middleware: failed to generate shared key: %w", skErr)
	}

	// 3. Encrypt the signed plaintext body.
	// Authorization header is NOT modified — external NP decrypts body first, then verifies Auth.
	encryptedString, encErr := cryptoutil.EncryptData(sharedKey, string(bodyBytes))
	if encErr != nil {
		log.Errorf(ctx, encErr, "outgoing-encryption-middleware: encryption failed")
		return nil, fmt.Errorf("outgoing-encryption-middleware: encryption failed: %w", encErr)
	}

	encryptedBytes := []byte(encryptedString)
	req.Body = io.NopCloser(bytes.NewBuffer(encryptedBytes))
	req.ContentLength = int64(len(encryptedBytes))

	log.Infof(ctx, "outgoing-encryption-middleware: body encrypted (%d bytes), Auth header preserved; forwarding to external NP",
		len(encryptedBytes))
	log.Infof(ctx, "outgoing-encryption-middleware: outgoing plaintext was: %s", string(bodyBytes))
	log.Infof(ctx, "outgoing-encryption-middleware: outgoing ciphertext: %s", encryptedString)

	return t.base.RoundTrip(req)
}
