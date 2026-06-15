package main

import (
	"context"
	"net/http"

	callbackredirect "github.com/ONDC-Official/automation-beckn-plugins/workbench-callback-redirect"
)

// middlewareProvider implements the beckn-onix middleware plugin provider:
// New returns a func(http.Handler) http.Handler.
type middlewareProvider struct{}

// New returns the callback-redirect middleware.
// config must contain "addr" (Redis address).
func (p middlewareProvider) New(ctx context.Context, c map[string]string) (func(http.Handler) http.Handler, error) {
	return callbackredirect.New(ctx, c)
}

// Provider is the exported symbol the beckn-onix plugin manager looks for.
var Provider = middlewareProvider{}
