package keymanager

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	ondccrypto "github.com/ONDC-Official/ondc-crypto-sdk-go"
	"github.com/beckn-one/beckn-onix/pkg/model"
	"github.com/beckn-one/beckn-onix/pkg/plugin/definition"
	"github.com/spf13/viper"
)

type Env struct {
	SubscriberID   string `mapstructure:"SUBSCRIBER_ID"` // SubscriberID is the identifier for the subscriber.
	UniqueKeyID    string `mapstructure:"UNIQUE_KEY_ID"` // UniqueKeyID is the identifier for the key pair.
	SigningPrivate string `mapstructure:"SIGNING_PRIVATE"` // SigningPrivate is the private key used for signing operations.
	SigningPublic  string `mapstructure:"SIGNING_PUBLIC"` // SigningPublic is the public key corresponding to the signing private key.
	EncrPrivate    string `mapstructure:"ENCR_PRIVATE"` // EncrPrivate is the private key used for encryption operations.
	EncrPublic     string `mapstructure:"ENCR_PUBLIC"` // EncrPublic is the public key corresponding to the encryption private key.
}

type KeyMgr struct {
	env *Env
}

type Config struct {

}

func New(ctx context.Context, cache definition.Cache, registryLookup definition.RegistryLookup, cfg *Config) (*KeyMgr, func() error, error) {
	mgr := &KeyMgr{
		env: NewEnv(),
	}
	return mgr, func() error { return nil }, nil
}

func (k *KeyMgr) GenerateKeyset() (*model.Keyset,error){
	return &model.Keyset{
		SubscriberID:   k.env.SubscriberID,
		UniqueKeyID:    k.env.UniqueKeyID,
		SigningPrivate: k.env.SigningPrivate,
		SigningPublic:  k.env.SigningPublic,
		EncrPrivate:    k.env.EncrPrivate,
		EncrPublic:     k.env.EncrPublic,
	},nil
}

func (k *KeyMgr) InsertKeyset(ctx context.Context, keyID string, keyset *model.Keyset) error {
	return nil
}

func (k *KeyMgr) Keyset(ctx context.Context, keyID string) (*model.Keyset, error) {
	return &model.Keyset{
		SubscriberID:   k.env.SubscriberID,
		UniqueKeyID:    k.env.UniqueKeyID,
		SigningPrivate: k.env.SigningPrivate,
		SigningPublic:  k.env.SigningPublic,
		EncrPrivate:    k.env.EncrPrivate,
		EncrPublic:     k.env.EncrPublic,
	}, nil
}

func (k *KeyMgr) DeleteKeyset(ctx context.Context, keyID string) error {
	return nil
}

func (k *KeyMgr) LookupNPKeys(ctx context.Context, subscriberID string, uniqueKeyID string) (signingPublicKey string, encrPublicKey string, err error) {
	// Prepare lookup request body
	requestBody := map[string]string{
		"subscriber_id": subscriberID,
		"ukId":          uniqueKeyID,
	}

	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create authorization header using ONDC crypto SDK
	authHeader, err := k.createAuthorizationHeader(string(bodyBytes))
	if err != nil {
		return "", "", fmt.Errorf("failed to create authorization header: %w", err)
	}

	// Perform lookup request
	registryURL := k.env.getRegistryURL()
	lookupURL := registryURL + "lookup"

	req, err := http.NewRequestWithContext(ctx, "POST", lookupURL, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return "", "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader)

	// Make HTTP request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("failed to perform lookup request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("lookup request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to read response body: %w", err)
	}

	// Log the raw response for debugging
	fmt.Printf("[LookupNPKeys] registry URL: %s | subscriber_id: %s | ukId: %s | raw response: %s\n",
		lookupURL, subscriberID, uniqueKeyID, string(respBody))

	var lookupResponse []struct {
		SigningPublicKey string `json:"signing_public_key"`
		EncrPublicKey   string `json:"encr_public_key"`
	}

	if err := json.Unmarshal(respBody, &lookupResponse); err != nil {
		return "", "", fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if len(lookupResponse) == 0 {
		return "", "", fmt.Errorf("no lookup results found for subscriber_id: %s, ukId: %s", subscriberID, uniqueKeyID)
	}

	return lookupResponse[0].SigningPublicKey, lookupResponse[0].EncrPublicKey, nil
}

// LookupNPKeysByDomain looks up NP signing and encryption public keys from the ONDC registry
// using subscriber_id + domain (instead of ukId).
// Used by the outgoing-encryption-middleware where ukId is not known for the counterparty.
func (k *KeyMgr) LookupNPKeysByDomain(ctx context.Context, subscriberID string, domain string) (signingPublicKey string, encrPublicKey string, err error) {
	// Prepare lookup request body using domain instead of ukId
	requestBody := map[string]string{
		"subscriber_id": subscriberID,
		"domain":        domain,
	}

	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create authorization header using ONDC crypto SDK
	authHeader, err := k.createAuthorizationHeader(string(bodyBytes))
	if err != nil {
		return "", "", fmt.Errorf("failed to create authorization header: %w", err)
	}

	// Perform lookup request
	registryURL := k.env.getRegistryURL()
	lookupURL := registryURL + "lookup"

	req, err := http.NewRequestWithContext(ctx, "POST", lookupURL, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return "", "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("failed to perform lookup request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("lookup request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to read response body: %w", err)
	}

	// Log the raw response for debugging
	fmt.Printf("[LookupNPKeysByDomain] registry URL: %s | subscriber_id: %s | domain: %s | raw response: %s\n",
		lookupURL, subscriberID, domain, string(respBody))

	var lookupResponse []struct {
		SigningPublicKey string `json:"signing_public_key"`
		EncrPublicKey   string `json:"encr_public_key"`
	}

	if err := json.Unmarshal(respBody, &lookupResponse); err != nil {
		return "", "", fmt.Errorf("failed to unmarshal response: %w — raw: %s", err, string(respBody))
	}

	if len(lookupResponse) == 0 {
		return "", "", fmt.Errorf("no lookup results found for subscriber_id: %s, domain: %s", subscriberID, domain)
	}

	return lookupResponse[0].SigningPublicKey, lookupResponse[0].EncrPublicKey, nil
}

func (k *KeyMgr) createAuthorizationHeader(body string) (string, error) {
	authHeader, err := ondccrypto.CreateAuthorizationHeader(ondccrypto.CreateAuthorizationHeaderParams{
		Body:                  body,
		PrivateKey:            k.env.SigningPrivate,
		SubscriberID:          k.env.SubscriberID,
		SubscriberUniqueKeyID: k.env.UniqueKeyID,
	})
	if err != nil {
		return "", fmt.Errorf("failed to create auth header: %w", err)
	}
	return authHeader, nil
}

func (e *Env) getRegistryURL() string {
	// Use IN_HOUSE_REGISTRY URL as specified
	registryURL := "https://preprod.registry.ondc.org/v2.0/"
	if customURL := viper.GetString("IN_HOUSE_REGISTRY"); customURL != "" {
		registryURL = customURL
	}
	return registryURL
}

func NewEnv() *Env {
	env := Env{}

	// Try to read .env file if present; do not panic if it's missing.
	viper.SetConfigFile(".env")
	if err := viper.ReadInConfig(); err != nil {
		// ignore missing/parse errors so we can rely on OS envs in containers
	}

	// Allow environment variables (useful for Docker/k8s). Environment
	// variables will override values from the .env file below where set.
	viper.AutomaticEnv()

	// Attempt to unmarshal whatever viper has (file + env). If Unmarshal
	// fails for some reason, fall back to reading individual keys.
	if err := viper.Unmarshal(&env); err != nil {
		env.SubscriberID = viper.GetString("SUBSCRIBER_ID")
		env.UniqueKeyID = viper.GetString("UNIQUE_KEY_ID")
		env.SigningPrivate = viper.GetString("SIGNING_PRIVATE")
		env.SigningPublic = viper.GetString("SIGNING_PUBLIC")
		env.EncrPrivate = viper.GetString("ENCR_PRIVATE")
		env.EncrPublic = viper.GetString("ENCR_PUBLIC")
	} else {
		// Ensure explicit OS env variables (if present) override values
		if v := viper.GetString("SUBSCRIBER_ID"); v != "" {
			env.SubscriberID = v
		}
		if v := viper.GetString("UNIQUE_KEY_ID"); v != "" {
			env.UniqueKeyID = v
		}
		if v := viper.GetString("SIGNING_PRIVATE"); v != "" {
			env.SigningPrivate = v
		}
		if v := viper.GetString("SIGNING_PUBLIC"); v != "" {
			env.SigningPublic = v
		}
		if v := viper.GetString("ENCR_PRIVATE"); v != "" {
			env.EncrPrivate = v
		}
		if v := viper.GetString("ENCR_PUBLIC"); v != "" {
			env.EncrPublic = v
		}
	}

	return &env
}

// GetEncrPrivateKey exposes the workbench's own encryption private key.
// Used by encryption middleware plugins so they can derive the shared AES key
// without needing the host to inject a KeyManager instance.
func (k *KeyMgr) GetEncrPrivateKey() string {
	return k.env.EncrPrivate
}