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

// VerifyResult summarizes live ARM & Monitor token minting or sealed envelope validation.
type VerifyResult struct {
	OK                bool           `json:"ok"`
	Sealed            bool           `json:"sealed,omitempty"`
	KeyID             string         `json:"keyId,omitempty"`
	VerifiedAtOnboard bool           `json:"verifiedAtOnboard,omitempty"`
	TenantID          string         `json:"tenantId"`
	ClientID          string         `json:"clientId"`
	ARMTokenOK        bool           `json:"armTokenOk,omitempty"`
	MonitorOK         bool           `json:"monitorTokenOk,omitempty"`
	Subscriptions     []Subscription `json:"subscriptions"`
	Note              string         `json:"note,omitempty"`
	Error             string         `json:"error,omitempty"`
}

// InspectSealedBundle checks whether a file is an encrypted rax-azure-sealed-bundle/v1 envelope
// and validates its structural integrity without requiring the server private key.
func InspectSealedBundle(path string) (*VerifyResult, bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read bundle file: %w", err)
	}
	var peek struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(raw, &peek); err != nil {
		return nil, false, fmt.Errorf("invalid bundle JSON: %w", err)
	}
	if peek.Schema != SealedBundleSchema {
		return nil, false, nil
	}

	var doc SealedOnboardBundle
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, true, fmt.Errorf("malformed sealed bundle: %w", err)
	}
	if doc.Alg != SealedBundleAlg || doc.KeyID == "" {
		return nil, true, errors.New("sealed bundle has invalid alg or keyId")
	}
	if doc.Sealed.EK == "" || doc.Sealed.IV == "" || doc.Sealed.CT == "" {
		return nil, true, errors.New("sealed bundle is missing encrypted payload fields")
	}
	if doc.Metadata.TenantID == "" || doc.Metadata.ClientID == "" {
		return nil, true, errors.New("sealed bundle metadata is missing tenantId or clientId")
	}

	subs := make([]Subscription, 0, len(doc.Metadata.Subscriptions))
	for _, s := range doc.Metadata.Subscriptions {
		subs = append(subs, Subscription{
			SubscriptionID: s.ID,
			DisplayName:    s.Name,
			State:          "Enabled",
			TenantID:       doc.Metadata.TenantID,
		})
	}

	return &VerifyResult{
		OK:                true,
		Sealed:            true,
		KeyID:             doc.KeyID,
		VerifiedAtOnboard: doc.Metadata.Verified,
		TenantID:          doc.Metadata.TenantID,
		ClientID:          doc.Metadata.ClientID,
		ARMTokenOK:        doc.Metadata.Verified,
		MonitorOK:         doc.Metadata.Verified,
		Subscriptions:     subs,
		Note:              "Encrypted with Rax platform public key (RSA-OAEP-256+AES-256-GCM); only Rax Console can decrypt clientSecret.",
	}, true, nil
}

// LoadBundleCredentials parses a legacy plaintext Rax onboarding bundle JSON (camelCase or snake_case).
func LoadBundleCredentials(path string) (*VerifyCredentials, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read bundle file: %w", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("invalid bundle JSON: %w", err)
	}
	if obj["schema"] == SealedBundleSchema {
		return nil, errors.New("bundle is sealed/encrypted and can only be decrypted by Rax Console")
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
