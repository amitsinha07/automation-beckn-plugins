package main

import (
	"context"

	"github.com/beckn-one/beckn-onix/pkg/plugin/definition"

	outgoingencrypt "github.com/ONDC-Official/automation-beckn-plugins/outgoing-encryption-middleware"
)

type outgoingEncryptionProvider struct{}

// New implements definition.TransportWrapperProvider.
// The host calls this once at startup to obtain a TransportWrapper that is then
// wired into the http.Client used by the mockTxnCaller handler.
func (p outgoingEncryptionProvider) New(ctx context.Context, config map[string]any) (definition.TransportWrapper, func(), error) {
	wrapper, cleanup, err := outgoingencrypt.New(ctx)
	if err != nil {
		return nil, nil, err
	}
	return wrapper, cleanup, nil
}

// Provider is the exported symbol the host uses to load this plugin.
var Provider = outgoingEncryptionProvider{}
