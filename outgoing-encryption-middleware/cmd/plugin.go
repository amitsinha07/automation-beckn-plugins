package main

import (
	"context"
	"net/http"

	outgoingencrypt "github.com/ONDC-Official/automation-beckn-plugins/outgoing-encryption-middleware"
)

type outgoingEncryptionProvider struct{}

func (p outgoingEncryptionProvider) New(ctx context.Context, c map[string]string) (func(http.Handler) http.Handler, error) {
	return outgoingencrypt.New(ctx)
}

// Provider is the exported symbol the host uses to load this plugin.
var Provider = outgoingEncryptionProvider{}
