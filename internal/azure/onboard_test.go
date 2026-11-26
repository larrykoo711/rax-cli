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
	var secretAddedAfterAssignments int32
	var lastAssignableScopes []string

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
					{"subscriptionId": "sub-2", "displayName": "Prod Sub 2", "state": "Enabled", "tenantId": tenantID},
					{"subscriptionId": "sub-disabled", "displayName": "Old Sub", "state": "Disabled", "tenantId": tenantID},
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/organization":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]any{
					{
						"id":          tenantID,
						"displayName": "HaiLiang Cloud",
						"verifiedDomains": []map[string]any{
							{"name": "hailiang01.onmicrosoft.com", "isInitial": true, "isDefault": true},
						},
					},
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
			if atomic.LoadInt32(&roleAssignments) >= 10 {
				atomic.StoreInt32(&secretAddedAfterAssignments, 1)
			}
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
			var body struct {
				Properties struct {
					AssignableScopes []string `json:"assignableScopes"`
				} `json:"properties"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			lastAssignableScopes = body.Properties.AssignableScopes
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
	bundlePath := filepath.Join(tmpDir, "rax-demo.rax.enc.json")

	var events []OnboardEvent
	sum, err := ob.Run(context.Background(), OnboardOptions{
		Slug:       "", // Omit --slug: must auto-derive from hailiang01.onmicrosoft.com!
		SecretDays: 7,
		Apply:      true,
		OutputPath: bundlePath,
		NowUTC:     func() time.Time { return time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC) },
		OnEvent:    func(ev OnboardEvent) { events = append(events, ev) },
	})
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if sum.Slug != "hailiang01" || sum.AppName != "rax-managed-sp-hailiang01" {
		t.Fatalf("expected auto-derived slug hailiang01 from *.onmicrosoft.com, got slug=%q appName=%q", sum.Slug, sum.AppName)
	}
	if sum.TenantDomain != "hailiang01.onmicrosoft.com" || sum.AuthorizedByEmail != "admin@example.com" || sum.TenantDisplayName != "HaiLiang Cloud" {
		t.Fatalf("expected tenantDomain/authorizedByEmail/displayName populated, got %+v", sum)
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
	if !sum.Applied || !sum.Sealed || !sum.Verified || sum.TenantID != tenantID || sum.ClientID != "app-client-1" {
		t.Fatalf("unexpected summary: %+v", sum)
	}
	if sum.SecretMasked != "***9876" {
		t.Fatalf("expected masked secret ***9876, got %s", sum.SecretMasked)
	}
	if len(sum.Subscriptions) != 2 || sum.Subscriptions[0].ID != "sub-1" || sum.Subscriptions[1].ID != "sub-2" {
		t.Fatalf("expected 2 enabled auto-discovered subscriptions, got %+v", sum.Subscriptions)
	}
	// Multi-subscription tenant must create ONLY ONE directory-unique custom freeze role covering BOTH subs.
	if atomic.LoadInt32(&customRolesCreated) != 1 {
		t.Fatalf("expected exactly 1 tenant-unique custom role created across 2 subs, got %d", customRolesCreated)
	}
	if len(lastAssignableScopes) != 2 || lastAssignableScopes[0] != "/subscriptions/sub-1" || lastAssignableScopes[1] != "/subscriptions/sub-2" {
		t.Fatalf("expected assignableScopes for both subscriptions, got %+v", lastAssignableScopes)
	}
	// 2 subs * 5 roles + 1 simulated PrincipalNotFound retry = 11 PUT calls
	if atomic.LoadInt32(&roleAssignments) != 11 {
		t.Fatalf("expected 11 role assignment calls (10 + 1 retry), got %d", roleAssignments)
	}
	// Secret must be minted strictly AFTER all RBAC assignments succeed.
	if atomic.LoadInt32(&secretAddedAfterAssignments) != 1 {
		t.Fatalf("expected client secret to be created strictly after RBAC assignments succeed")
	}

	info, err := os.Stat(bundlePath)
	if err != nil {
		t.Fatalf("stat bundle: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected chmod 0600, got %o", info.Mode().Perm())
	}

	// Ensure plaintext secret NEVER appears on disk in the default sealed bundle!
	rawOnDisk, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	if strings.Contains(string(rawOnDisk), "super-secret-value-9876") {
		t.Fatalf("plaintext clientSecret leaked to disk in sealed bundle!")
	}

	// Verify sealed envelope inspection succeeds cleanly.
	sealedRes, isSealed, err := InspectSealedBundle(bundlePath)
	if err != nil || !isSealed || !sealedRes.OK || !sealedRes.VerifiedAtOnboard {
		t.Fatalf("InspectSealedBundle failed: res=%+v sealed=%v err=%v", sealedRes, isSealed, err)
	}
}
