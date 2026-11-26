package azure

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEnsureRoleAssignmentRetriesPerRequestTimeoutAndAcceptsRoleAssignmentExists(t *testing.T) {
	var attempts int32
	var seenPaths []string
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		mu.Lock()
		seenPaths = append(seenPaths, r.URL.Path)
		mu.Unlock()

		if n == 1 {
			// Simulate ARM accepting the PUT server-side but taking longer than per-request timeout to return headers.
			time.Sleep(180 * time.Millisecond)
			w.WriteHeader(http.StatusCreated)
			return
		}
		// Replay with the exact same assignment ID returns 409 RoleAssignmentExists -> must succeed idempotently.
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":{"code":"RoleAssignmentExists","message":"The role assignment already exists."}}`))
	}))
	defer srv.Close()

	var retries []RetryNotice
	arm := &ARMClient{
		BaseURL:        srv.URL,
		HTTP:           srv.Client(),
		RequestTimeout: 60 * time.Millisecond,
		MaxRetries:     4,
		Sleep:          func(context.Context, time.Duration) error { return nil },
		OnRetry:        func(n RetryNotice) { retries = append(retries, n) },
	}

	err := arm.EnsureRoleAssignment(context.Background(), "tok", "sub-1", "sp-oid-1", "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7")
	if err != nil {
		t.Fatalf("expected idempotent success after timeout + 409 RoleAssignmentExists, got: %v", err)
	}
	if atomic.LoadInt32(&attempts) != 2 {
		t.Fatalf("expected 2 attempts, got %d", attempts)
	}
	if len(seenPaths) != 2 || seenPaths[0] != seenPaths[1] {
		t.Fatalf("expected identical deterministic assignment GUID across retries, got %v", seenPaths)
	}
	if len(retries) != 1 || retries[0].Reason != "arm_request_timeout" {
		t.Fatalf("expected 1 arm_request_timeout retry notice, got %+v", retries)
	}
}

func TestEnsureRoleAssignmentRetries429RetryAfterAnd503(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		switch n {
		case 1:
			w.Header().Set("Retry-After", "4")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":{"code":"TooManyRequests"}}`))
		case 2:
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":{"code":"ServiceUnavailable"}}`))
		default:
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"ok"}`))
		}
	}))
	defer srv.Close()

	var waits []time.Duration
	var reasons []string
	arm := &ARMClient{
		BaseURL:        srv.URL,
		HTTP:           srv.Client(),
		RequestTimeout: 5 * time.Second,
		MaxRetries:     5,
		Sleep: func(_ context.Context, d time.Duration) error {
			waits = append(waits, d)
			return nil
		},
		OnRetry: func(n RetryNotice) {
			reasons = append(reasons, n.Reason)
		},
	}

	if err := arm.EnsureRoleAssignment(context.Background(), "tok", "sub-1", "sp-1", "role-1"); err != nil {
		t.Fatalf("expected recovery after 429 and 503, got: %v", err)
	}
	if atomic.LoadInt32(&attempts) != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
	if len(waits) != 2 || waits[0] != 4*time.Second {
		t.Fatalf("expected first retry to respect Retry-After=4s, got waits=%v", waits)
	}
	if len(reasons) != 2 || reasons[0] != "arm_throttled_429" || reasons[1] != "arm_http_503" {
		t.Fatalf("unexpected retry reasons: %v", reasons)
	}
}

func TestEnsureRoleAssignmentDoesNotRetry403OrExhaustedOrCancellation(t *testing.T) {
	t.Run("403 fails immediately without retries", func(t *testing.T) {
		var attempts int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&attempts, 1)
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":{"code":"AuthorizationFailed"}}`))
		}))
		defer srv.Close()

		arm := &ARMClient{
			BaseURL: srv.URL,
			HTTP:    srv.Client(),
			Sleep:   func(context.Context, time.Duration) error { return nil },
		}
		err := arm.EnsureRoleAssignment(context.Background(), "tok", "sub-1", "sp-1", "role-1")
		if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
			t.Fatalf("expected HTTP 403 error, got: %v", err)
		}
		if atomic.LoadInt32(&attempts) != 1 {
			t.Fatalf("permanent 403 must not retry; got %d attempts", attempts)
		}
	})

	t.Run("retry exhaustion returns error after MaxRetries", func(t *testing.T) {
		var attempts int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&attempts, 1)
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer srv.Close()

		arm := &ARMClient{
			BaseURL:    srv.URL,
			HTTP:       srv.Client(),
			MaxRetries: 3,
			Sleep:      func(context.Context, time.Duration) error { return nil },
		}
		err := arm.EnsureRoleAssignment(context.Background(), "tok", "sub-1", "sp-1", "role-1")
		if err == nil {
			t.Fatalf("expected error after retry exhaustion")
		}
		if atomic.LoadInt32(&attempts) != 3 {
			t.Fatalf("expected exactly 3 attempts, got %d", attempts)
		}
	})

	t.Run("caller cancellation aborts immediately without retrying", func(t *testing.T) {
		var attempts int32
		ctx, cancel := context.WithCancel(context.Background())
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&attempts, 1)
			cancel()
			time.Sleep(100 * time.Millisecond)
		}))
		defer srv.Close()

		arm := &ARMClient{
			BaseURL:        srv.URL,
			HTTP:           srv.Client(),
			RequestTimeout: 5 * time.Second,
			MaxRetries:     4,
			Sleep:          func(context.Context, time.Duration) error { return nil },
		}
		err := arm.EnsureRoleAssignment(ctx, "tok", "sub-1", "sp-1", "role-1")
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got: %v", err)
		}
		if atomic.LoadInt32(&attempts) != 1 {
			t.Fatalf("caller cancellation must not retry; got %d attempts", attempts)
		}
	})
}

func TestOnboardMidSubscriptionFailureReportsExactCompletedAndPendingCounts(t *testing.T) {
	const tenantID = "e77104bd-f595-4cc6-b1f9-6a076d261761"
	var secretCalled int32
	var sub2Puts int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/devicecode"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user_code": "WXYZ-9999", "device_code": "dc-1",
				"verification_uri": "https://microsoft.com/devicelogin", "expires_in": 600, "interval": 1,
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": makeFakeJWT(tenantID), "refresh_token": "rt-1", "expires_in": 3600,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/organization":
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{}})
		case r.Method == http.MethodGet && r.URL.Path == "/subscriptions":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]string{
					{"subscriptionId": "sub-ok", "displayName": "Sub OK", "state": "Enabled", "tenantId": tenantID},
					{"subscriptionId": "sub-fail", "displayName": "Sub Fail", "state": "Enabled", "tenantId": tenantID},
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/applications":
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]string{{"id": "app-1", "appId": "cid-1", "displayName": "rax-managed-sp-demo"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/servicePrincipals":
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]string{{"id": "sp-1", "appId": "cid-1"}}})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/roleDefinitions"):
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{}})
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/roleDefinitions/"):
			_ = json.NewEncoder(w).Encode(map[string]string{"id": r.URL.Path})
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/subscriptions/sub-ok/providers/Microsoft.Authorization/roleAssignments/"):
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"ok"}`))
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/subscriptions/sub-fail/providers/Microsoft.Authorization/roleAssignments/"):
			// Fail on the 3rd role of sub-fail with permanent 403 -> sub-fail MUST NOT count as completed!
			if atomic.AddInt32(&sub2Puts, 1) >= 3 {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":{"code":"AuthorizationFailed"}}`))
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"ok"}`))
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/addPassword"):
			atomic.StoreInt32(&secretCalled, 1)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	noSleep := func(context.Context, time.Duration) error { return nil }
	ob := &Onboarder{
		Auth:  &AuthClient{LoginBaseURL: srv.URL, HTTP: srv.Client(), Sleep: noSleep},
		Graph: &GraphClient{BaseURL: srv.URL, HTTP: srv.Client()},
		ARM:   &ARMClient{BaseURL: srv.URL, HTTP: srv.Client(), Sleep: noSleep, MaxRetries: 2},
	}

	var progressEvents []OnboardEvent
	_, err := ob.Run(context.Background(), OnboardOptions{
		Slug:        "demo",
		SecretDays:  30,
		Apply:       true,
		Concurrency: 1, // Deterministic order: sub-ok finishes completely, then sub-fail fails on role 3/5.
		OnEvent: func(ev OnboardEvent) {
			if ev.Event == "progress" {
				progressEvents = append(progressEvents, ev)
			}
		},
	})
	if err == nil {
		t.Fatalf("expected failure on sub-fail")
	}
	var failErr *OnboardFailureError
	if !errors.As(err, &failErr) {
		t.Fatalf("expected *OnboardFailureError, got %T: %v", err, err)
	}
	if failErr.Step != "4/5" || failErr.Completed != 1 || failErr.Total != 2 || failErr.Pending != 1 || failErr.SecretCreated {
		t.Fatalf("unexpected failure accounting: %+v", failErr)
	}
	if len(progressEvents) != 1 || progressEvents[0].Completed != 1 || progressEvents[0].Total != 2 {
		t.Fatalf("expected exactly 1 progress event (1/2), got %+v", progressEvents)
	}
	if atomic.LoadInt32(&secretCalled) != 0 {
		t.Fatalf("secret creation must NOT start when RBAC fails mid-subscription")
	}
}
