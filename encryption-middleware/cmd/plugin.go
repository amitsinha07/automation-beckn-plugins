package main

import (
	"context"
	"net/http"

	encryptionmiddleware "github.com/ONDC-Official/automation-beckn-plugins/encryption-middleware"
)

type encryptionMiddlewareProvider struct{}

func (p encryptionMiddlewareProvider) New(ctx context.Context, c map[string]string) (func(http.Handler) http.Handler, error) {
	return encryptionmiddleware.New(ctx)
}

// Provider is the exported symbol the host uses to load this plugin.
var Provider = encryptionMiddlewareProvider{}
