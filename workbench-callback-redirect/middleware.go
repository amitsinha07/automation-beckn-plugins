package callbackredirect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/beckn-one/beckn-onix/pkg/log"
	"github.com/redis/go-redis/v9"
)

// Key prefixes and TTL form a cross-service contract with the automation-frontend
// backend and the Node api-service callbackController — keep in sync.
//   redirection_url:{subscriberUrl} -> full workbench URL (written by frontend backend)
//   form_completed:{sessionId}      -> completion payload  (written here)
const (
	formCompletedPrefix  = "form_completed"
	redirectionURLPrefix = "redirection_url"
	completionTTL        = 3600 * time.Second
)

// CallbackRedirect is a middleware for the public GET /callback. It derives its
// own subscriberUrl from the request, looks up the workbench URL the frontend
// stored under redirection_url:{subscriberUrl}, extracts sessionId from that URL,
// writes form_completed:{sessionId}, and issues an immediate HTTP 302 redirect
// back to the workbench. It never calls next — the request ends at the redirect.
type CallbackRedirect struct {
	redis *redis.Client
	ttl   time.Duration
}

// New initialises the middleware from the plugin config map.
// Required config key: "addr" — Redis address (e.g. "localhost:6379").
// Optional env vars:   REDIS_PASSWORD, REDIS_USERNAME
func New(ctx context.Context, config map[string]string) (func(http.Handler) http.Handler, error) {
	addr := config["addr"]
	if addr == "" {
		return nil, fmt.Errorf("callback-redirect: 'addr' (Redis address) is required in config")
	}

	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: os.Getenv("REDIS_PASSWORD"),
		Username: os.Getenv("REDIS_USERNAME"),
		DB:       0,
	})
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("callback-redirect: failed to connect to Redis at %s: %w", addr, err)
	}
	log.Infof(ctx, "callback-redirect: Redis connection established at %s", addr)

	m := &CallbackRedirect{redis: client, ttl: completionTTL}
	return m.handler, nil
}

func (m *CallbackRedirect) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// 0. GET-only: the callback is browser-navigated, so reject any other method.
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		// 1. Derive our own subscriberUrl from the callback's own URL
		//    ({subscriberUrl}/callback). X-Forwarded-* first so it works behind a proxy.
		proto := firstNonEmpty(r.Header.Get("X-Forwarded-Proto"), schemeOf(r))
		host := firstNonEmpty(r.Header.Get("X-Forwarded-Host"), r.Host)
		own := fmt.Sprintf("%s://%s%s", proto, host, r.URL.Path)
		subscriberURL := strings.TrimSuffix(strings.TrimRight(own, "/"), "/callback")

		// 2. Look up the stored workbench URL
		redirectURL, err := m.redis.Get(ctx, fmt.Sprintf("%s:%s", redirectionURLPrefix, subscriberURL)).Result()
		if err != nil || redirectURL == "" {
			log.Warnf(ctx, "callback-redirect: no redirection URL for subscriber %s", subscriberURL)
			http.Error(w, "No redirection URL found for this subscriber.", http.StatusNotFound)
			return
		}

		// 3. sessionId lives inside the stored workbench URL
		parsed, perr := url.Parse(redirectURL)
		if perr != nil || parsed.Query().Get("sessionId") == "" {
			http.Error(w, "Stored redirection URL is missing sessionId.", http.StatusBadRequest)
			return
		}
		sessionID := parsed.Query().Get("sessionId")

		// 4. Reaching the callback means completion; only explicit success=false fails.
		success := r.URL.Query().Get("success") != "false"

		// 5. Write form_completed:{sessionId}
		body, mErr := json.Marshal(map[string]interface{}{
			"completed": true,
			"success":   success,
			"message":   "",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		})
		if mErr != nil {
			http.Error(w, "Error processing callback.", http.StatusInternalServerError)
			return
		}
		if err := m.redis.Set(ctx, fmt.Sprintf("%s:%s", formCompletedPrefix, sessionID), string(body), m.ttl).Err(); err != nil {
			log.Errorf(ctx, err, "callback-redirect: failed to write completion for session %s", sessionID)
			http.Error(w, "Error processing callback.", http.StatusInternalServerError)
			return
		}

		log.Infof(ctx, "callback-redirect: completion set, redirecting session %s -> %s", sessionID, redirectURL)

		// 6. Immediate HTTP 302 — do NOT call next; the request ends here.
		http.Redirect(w, r, redirectURL, http.StatusFound)
	})
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func schemeOf(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}
