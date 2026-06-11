package main

import (
	"context"

	callbackreceiver "github.com/ONDC-Official/automation-beckn-plugins/workbench-callback"
	"github.com/beckn-one/beckn-onix/pkg/plugin/definition"
)

// StepProvider implements definition.StepProvider for the callback receiver step.
type StepProvider struct{}

// New creates and returns a new CallbackReceiver step instance.
// config must contain "addr" (Redis address).
func (p StepProvider) New(ctx context.Context, config map[string]string) (definition.Step, func(), error) {
	return callbackreceiver.New(ctx, config)
}

// Provider is the exported symbol the beckn-onix plugin manager looks for.
var Provider = StepProvider{}
