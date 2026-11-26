package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// VerifyCredentials holds the Service Principal inputs needed for live verification.
type VerifyCredentials struct {
	TenantID     string
	ClientID     string
	ClientSecret string
}

// VerifyResult summarizes live ARM & Monitor token minting and visible subscriptions.
type VerifyResult struct {
	OK            bool           `json:"ok"`
	TenantID      string         `json:"tenantId"`
	ClientID      string         `json:"clientId"`
	ARMTokenOK    bool           `json:"armTokenOk"`
	MonitorOK     bool           `json:"monitorTokenOk"`
	Subscriptions []Subscription `json:"subscriptions"`
	Error         string         `json:"error,omitempty"`
}

// LoadBundleCredentials parses a Rax onboarding bundle JSON (camelCase or snake_case).
func LoadBundleCredentials(path string) (*VerifyCredentials, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read bundle file: %w", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("invalid bundle JSON: %w", err)
	}
	pick := func(keys ...string) string {
		for _, k := range keys {
			if s, ok := obj[k].(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
		return ""
	}
	creds := &VerifyCredentials{
		TenantID:     pick("tenantId", "tenant_id"),
		ClientID:     pick("clientId", "client_id"),
		ClientSecret: pick("clientSecret", "client_secret"),
	}
	if creds.TenantID == "" || creds.ClientID == "" || creds.ClientSecret == "" {
		return nil, errors.New("bundle is missing tenantId, clientId, or clientSecret")
	}
	return creds, nil
}

// Verify tests a Service Principal live against Entra ARM token, Monitor Data Plane token,
// and ARM subscription discovery.
func (o *Onboarder) Verify(ctx context.Context, creds VerifyCredentials) (*VerifyResult, error) {
	res := &VerifyResult{
		TenantID: creds.TenantID,
		ClientID: creds.ClientID,
	}
	if creds.TenantID == "" || creds.ClientID == "" || creds.ClientSecret == "" {
		return nil, errors.New("tenantId, clientId, and clientSecret are required")
	}

	armTok, err := o.Auth.FetchServicePrincipalToken(ctx, creds.TenantID, creds.ClientID, creds.ClientSecret, ScopeARMApp)
	if err != nil {
		res.Error = fmt.Sprintf("ARM token failed: %v", err)
		return res, err
	}
	res.ARMTokenOK = true

	if _, err := o.Auth.FetchServicePrincipalToken(ctx, creds.TenantID, creds.ClientID, creds.ClientSecret, ScopeMonitorApp); err != nil {
		res.Error = fmt.Sprintf("Monitor Data Plane token failed: %v", err)
		return res, err
	}
	res.MonitorOK = true

	subs, err := o.ARM.ListSubscriptions(ctx, armTok.AccessToken)
	if err != nil {
		res.Error = fmt.Sprintf("List subscriptions failed: %v", err)
		return res, err
	}
	res.Subscriptions = subs
	res.OK = true
	return res, nil
}
