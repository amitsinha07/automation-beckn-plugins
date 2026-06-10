package callbackreceiver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/beckn-one/beckn-onix/pkg/log"
	"github.com/beckn-one/beckn-onix/pkg/model"
	"github.com/redis/go-redis/v9"
)

// Key prefixes and TTL form a cross-service contract with the
// automation-frontend backend's checkFormCompletion poller and the
// Node api-service's callbackFormService — keep in sync.
const (
	formCompletedPrefix = "form_completed"
	latestFormPrefix    = "latest_form"
	completionTTL       = 3600 * time.Second
)

// callbackRequest represents the incoming callback body.
// Body format (custom, not Beckn): { transaction_id, form_id, success, message }
// success accepts boolean true/false OR string "true"/"false", mirroring the
// Node api-service's callbackController normalization.
type callbackRequest struct {
	TransactionID string          `json:"transaction_id"`
	FormID        string          `json:"form_id"`
	Success       json.RawMessage `json:"success"`
	Message       string          `json:"message"`
}

// callbackResponse is the JSON body sent back to the caller.
type callbackResponse struct {
	Success       bool   `json:"success"`
	Message       string `json:"message"`
	TransactionID string `json:"transaction_id,omitempty"`
	Timestamp     string `json:"timestamp,omitempty"`
}

// normalizeSuccess mirrors TS: success === true || success === "true"
func normalizeSuccess(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return b
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s == "true"
	}
	return false
}

// CallbackReceiver implements definition.Step for the /callback endpoint.
// It is fully public — no Authorization header required.
// On success it stores form completion data in Redis and returns a custom JSON response.
type CallbackReceiver struct {
	redis *redis.Client
	ttl   time.Duration
}

// New initialises a CallbackReceiver from the plugin config map.
// Required config key: "addr" — Redis address (e.g. "localhost:6379").
// Optional env vars:   REDIS_PASSWORD, REDIS_USERNAME
func New(ctx context.Context, config map[string]string) (*CallbackReceiver, func(), error) {
	addr := config["addr"]
	if addr == "" {
		return nil, nil, fmt.Errorf("callback receiver: 'addr' (Redis address) is required in config")
	}

	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: os.Getenv("REDIS_PASSWORD"),
		Username: os.Getenv("REDIS_USERNAME"),
		DB:       0,
	})

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, nil, fmt.Errorf("callback receiver: failed to connect to Redis at %s: %w", addr, err)
	}

	log.Infof(ctx, "callback receiver: Redis connection established at %s", addr)

	closer := func() {
		if err := client.Close(); err != nil {
			log.Errorf(context.Background(), err, "callback receiver: error closing Redis connection")
		}
	}

	return &CallbackReceiver{
		redis: client,
		ttl:   completionTTL,
	}, closer, nil
}

// Run implements definition.Step.
// Parses { transaction_id, form_id, success, message } from the request body,
// validates transaction_id and form_id, stores form completion data in Redis
// under "form_completed:{transaction_id}:{form_id}" plus a pointer key
// "latest_form:{transaction_id}", and writes a custom JSON response.
func (c *CallbackReceiver) Run(ctx *model.StepContext) error {
	// 1. Parse custom request body
	var req callbackRequest
	if err := json.Unmarshal(ctx.Body, &req); err != nil {
		log.Errorf(ctx, err, "callback: failed to parse request body")
		return c.sendResponse(ctx, callbackResponse{
			Success: false,
			Message: "Invalid request body",
		})
	}

	log.Infof(ctx, "callback received: transaction_id=%s form_id=%s success=%s message=%s",
		req.TransactionID, req.FormID, string(req.Success), req.Message)

	// 2. Validate required fields (mirrors TS callbackController)
	if req.TransactionID == "" || req.FormID == "" {
		log.Warnf(ctx, "callback: missing transaction_id or form_id in request body")
		return c.sendResponse(ctx, callbackResponse{
			Success: false,
			Message: "Missing required fields: transaction_id, form_id",
		})
	}

	// 3. Build Redis value
	completionKey := fmt.Sprintf("%s:%s:%s", formCompletedPrefix, req.TransactionID, req.FormID)
	pointerKey := fmt.Sprintf("%s:%s", latestFormPrefix, req.TransactionID)
	data := map[string]interface{}{
		"completed": true,
		"form_id":   req.FormID,
		"success":   normalizeSuccess(req.Success),
		"message":   req.Message,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		log.Errorf(ctx, err, "callback: failed to marshal completion data")
		return c.sendResponse(ctx, callbackResponse{
			Success: false,
			Message: fmt.Sprintf("Error processing callback: %s", err.Error()),
		})
	}

	// 4. Store in Redis with TTL 3600s.
	// Completion data must be written before the pointer so that a pointer
	// read by the poller always references existing data.
	if err := c.redis.Set(ctx, completionKey, string(dataBytes), c.ttl).Err(); err != nil {
		log.Errorf(ctx, err, "callback: failed to store key=%s in Redis", completionKey)
		return c.sendResponse(ctx, callbackResponse{
			Success: false,
			Message: fmt.Sprintf("Error processing callback: %s", err.Error()),
		})
	}
	if err := c.redis.Set(ctx, pointerKey, req.FormID, c.ttl).Err(); err != nil {
		log.Errorf(ctx, err, "callback: failed to store key=%s in Redis", pointerKey)
		return c.sendResponse(ctx, callbackResponse{
			Success: false,
			Message: fmt.Sprintf("Error processing callback: %s", err.Error()),
		})
	}

	log.Infof(ctx, "callback: completion flag set in Redis completionKey=%s pointerKey=%s transaction_id=%s form_id=%s",
		completionKey, pointerKey, req.TransactionID, req.FormID)

	// 5. Return success response
	return c.sendResponse(ctx, callbackResponse{
		Success:       true,
		Message:       "Callback received and recorded",
		TransactionID: req.TransactionID,
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
	})
}

// sendResponse encodes resp as base64 in the "custom-response-body" cookie and
// sets a non-proxy route so the beckn-onix framework delivers the custom JSON
// instead of a plain ACK.
func (c *CallbackReceiver) sendResponse(ctx *model.StepContext, resp callbackResponse) error {
	respBytes, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("callback: failed to marshal response: %w", err)
	}

	ctx.Request.AddCookie(&http.Cookie{
		Name:  "custom-response-body",
		Value: base64.StdEncoding.EncodeToString(respBytes),
	})

	// A non-proxy route with an empty TargetType causes the framework to:
	//   1. Register a no-op post-response hook (nothing forwarded)
	//   2. Read the custom-response-body cookie and send it as the HTTP response
	ctx.Route = &model.Route{
		ActAsProxy: false,
		TargetType: "",
	}

	return nil
}
