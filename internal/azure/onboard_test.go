package azure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func makeFakeJWT(tid string) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload, _ := json.Marshal(map[string]string{"tid": tid, "upn": "admin@example.com"})
	return hdr + "." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

func TestOnboardDryRunMakesZeroNetworkCalls(t *testing.T) {
	called := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ob := &Onboarder{
		Auth:  &AuthClient{LoginBaseURL: srv.URL, HTTP: srv.Client()},
		Graph: &GraphClient{BaseURL: srv.URL, HTTP: srv.Client()},
		ARM:   &ARMClient{BaseURL: srv.URL, HTTP: srv.Client()},
	}

	sum, err := ob.Run(context.Background(), OnboardOptions{
		Slug:       "hailiang01",
		SecretDays: 90,
		Apply:      false,
	})
	if err != nil {
		t.Fatalf("dry-run failed: %v", err)
	}
	if called != 0 {
		t.Fatalf("expected 0 network calls in dry-run, got %d", called)
	}
	if sum.Applied {
		t.Fatalf("expected Applied=false")
	}
	if sum.AppName != "rax-managed-sp-hailiang01" {
		t.Fatalf("unexpected AppName: %s", sum.AppName)
	}
	if len(sum.RolesPerSub) != 5 {
		t.Fatalf("expected 5 roles per sub, got %d", len(sum.RolesPerSub))
	}
}

func TestOnboardApplyAutoDiscoversSubscriptionsAndWritesChmod600Bundle(t *testing.T) {
	const tenantID = "e77104bd-f595-4cc6-b1f9-6a076d261761"
	var pollCount int32
	var roleAssignments int32
	var customRolesCreated int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/devicecode"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user_code":        "ABCD-1234",
				"device_code":      "dev-code-1",
				"verification_uri": "https://microsoft.com/devicelogin",
				"expires_in":       600,
				"interval":         1,
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			_ = r.ParseForm()
			gt := r.FormValue("grant_type")
			if gt == "urn:ietf:params:oauth:grant-type:device_code" {
				if atomic.AddInt32(&pollCount, 1) == 1 {
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token":  makeFakeJWT(tenantID),
					"refresh_token": "refresh-tok-1",
					"expires_in":    3600,
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "tok-" + r.FormValue("scope"),
				"expires_in":   3600,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/subscriptions":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]string{
					{"subscriptionId": "sub-1", "displayName": "Prod Sub 1", "state": "Enabled", "tenantId": tenantID},
					{"subscriptionId": "sub-disabled", "displayName": "Old Sub", "state": "Disabled", "tenantId": tenantID},
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/applications":
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{}})
		case r.Method == http.MethodPost && r.URL.Path == "/applications":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"id":          "app-oid-1",
				"appId":       "app-client-1",
				"displayName": "rax-managed-sp-demo",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/servicePrincipals":
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{}})
		case r.Method == http.MethodPost && r.URL.Path == "/servicePrincipals":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"id":    "sp-oid-1",
				"appId": "app-client-1",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/applications/app-oid-1/addPassword":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"secretText":  "super-secret-value-9876",
				"endDateTime": "2027-11-26T00:00:00Z",
			})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/roleDefinitions"):
			if strings.Contains(r.URL.RawQuery, "Rax+Foundry+Freeze+Operator") || strings.Contains(r.URL.RawQuery, "Rax%20Foundry%20Freeze%20Operator") {
				_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]string{{"id": "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/role-def-1"}},
			})
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/roleDefinitions/"):
			atomic.AddInt32(&customRolesCreated, 1)
			_ = json.NewEncoder(w).Encode(map[string]string{"id": r.URL.Path})
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/roleAssignments/"):
			if atomic.AddInt32(&roleAssignments, 1) == 1 {
				// Simulate Entra SP replication delay on first assignment
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "PrincipalNotFound"}})
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"id": r.URL.Path})
		default:
			t.Errorf("unexpected request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	noSleep := func(context.Context, time.Duration) error { return nil }
	ob := &Onboarder{
		Auth:  &AuthClient{LoginBaseURL: srv.URL, HTTP: srv.Client(), Sleep: noSleep},
		Graph: &GraphClient{BaseURL: srv.URL, HTTP: srv.Client()},
		ARM:   &ARMClient{BaseURL: srv.URL, HTTP: srv.Client(), Sleep: noSleep},
	}

	tmpDir := t.TempDir()
	bundlePath := filepath.Join(tmpDir, "rax-onboard-bundle.json")

	var events []OnboardEvent
	sum, err := ob.Run(context.Background(), OnboardOptions{
		Slug:       "demo",
		SecretDays: 7,
		Apply:      true,
		OutputPath: bundlePath,
		NowUTC:     func() time.Time { return time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC) },
		OnEvent:    func(ev OnboardEvent) { events = append(events, ev) },
	})
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	hasDeviceCodeEvent := false
	for _, ev := range events {
		if ev.Event == "device_code" && ev.UserCode == "ABCD-1234" && ev.VerificationURI == "https://microsoft.com/devicelogin" {
			hasDeviceCodeEvent = true
		}
	}
	if !hasDeviceCodeEvent {
		t.Fatalf("expected structured device_code event in agent mode, got %+v", events)
	}
	if !sum.Applied || sum.TenantID != tenantID || sum.ClientID != "app-client-1" {
		t.Fatalf("unexpected summary: %+v", sum)
	}
	if sum.SecretMasked != "***9876" {
		t.Fatalf("expected masked secret ***9876, got %s", sum.SecretMasked)
	}
	if len(sum.Subscriptions) != 1 || sum.Subscriptions[0].ID != "sub-1" || sum.Subscriptions[0].Name != "Prod Sub 1" {
		t.Fatalf("expected 1 enabled auto-discovered subscription, got %+v", sum.Subscriptions)
	}
	if atomic.LoadInt32(&customRolesCreated) != 1 {
		t.Fatalf("expected 1 custom role created, got %d", customRolesCreated)
	}
	// 5 roles + 1 simulated PrincipalNotFound retry = 6 PUT calls
	if atomic.LoadInt32(&roleAssignments) != 6 {
		t.Fatalf("expected 6 role assignment calls (5 + 1 retry), got %d", roleAssignments)
	}

	info, err := os.Stat(bundlePath)
	if err != nil {
		t.Fatalf("stat bundle: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected chmod 0600, got %o", info.Mode().Perm())
	}

	// Verify round-trip LoadBundleCredentials + Verify()
	creds, err := LoadBundleCredentials(bundlePath)
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	vres, err := ob.Verify(context.Background(), *creds)
	if err != nil || !vres.OK || !vres.ARMTokenOK || !vres.MonitorOK || len(vres.Subscriptions) != 2 {
		t.Fatalf("verify failed: res=%+v err=%v", vres, err)
	}
}
