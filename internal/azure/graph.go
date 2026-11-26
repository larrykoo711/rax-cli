package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GraphClient manages single-tenant Entra App Registrations, Service Principals, and Client Secrets.
type GraphClient struct {
	BaseURL string
	HTTP    *http.Client
}

// Application represents an Entra App Registration.
type Application struct {
	ObjectID    string `json:"id"`
	AppID       string `json:"appId"`
	DisplayName string `json:"displayName"`
}

// ServicePrincipal represents an Entra Enterprise Application / Service Principal.
type ServicePrincipal struct {
	ObjectID string `json:"id"`
	AppID    string `json:"appId"`
}

// PasswordCredential holds a freshly minted client secret from addPassword.
type PasswordCredential struct {
	SecretText  string `json:"secretText"`
	EndDateTime string `json:"endDateTime"`
	KeyID       string `json:"keyId"`
}

// NewGraphClient constructs a GraphClient with default v1.0 base URL.
func NewGraphClient(httpClient *http.Client) *GraphClient {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &GraphClient{
		BaseURL: DefaultGraphBaseURL,
		HTTP:    httpClient,
	}
}

func (g *GraphClient) baseURL() string {
	b := strings.TrimRight(g.BaseURL, "/")
	if b == "" {
		return DefaultGraphBaseURL
	}
	return b
}

func (g *GraphClient) doJSON(ctx context.Context, token, method, endpoint string, payload any, out any) error {
	var bodyReader io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := g.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("graph %s %s failed (HTTP %d): %s", method, endpoint, resp.StatusCode, trimBody(body))
	}
	if out != nil && len(body) > 0 {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("decode graph response: %w", err)
		}
	}
	return nil
}

// EnsureApplication idempotently finds or creates a single-tenant (AzureADMyOrg) App Registration.
func (g *GraphClient) EnsureApplication(ctx context.Context, token, displayName string) (*Application, bool, error) {
	escaped := strings.ReplaceAll(displayName, "'", "''")
	q := url.Values{}
	q.Set("$filter", fmt.Sprintf("displayName eq '%s'", escaped))
	q.Set("$select", "id,appId,displayName")
	listURL := fmt.Sprintf("%s/applications?%s", g.baseURL(), q.Encode())

	var listResp struct {
		Value []Application `json:"value"`
	}
	if err := g.doJSON(ctx, token, http.MethodGet, listURL, nil, &listResp); err != nil {
		return nil, false, fmt.Errorf("lookup existing app registration: %w", err)
	}
	if len(listResp.Value) > 0 {
		app := listResp.Value[0]
		return &app, false, nil
	}

	createURL := fmt.Sprintf("%s/applications", g.baseURL())
	var created Application
	if err := g.doJSON(ctx, token, http.MethodPost, createURL, map[string]any{
		"displayName":    displayName,
		"signInAudience": "AzureADMyOrg",
	}, &created); err != nil {
		return nil, false, fmt.Errorf("create app registration: %w", err)
	}
	if created.ObjectID == "" || created.AppID == "" {
		return nil, false, errors.New("graph created application without id/appId")
	}
	return &created, true, nil
}

// EnsureServicePrincipal idempotently finds or creates the Service Principal for an appId.
func (g *GraphClient) EnsureServicePrincipal(ctx context.Context, token, appID string) (*ServicePrincipal, bool, error) {
	escaped := strings.ReplaceAll(appID, "'", "''")
	q := url.Values{}
	q.Set("$filter", fmt.Sprintf("appId eq '%s'", escaped))
	q.Set("$select", "id,appId")
	listURL := fmt.Sprintf("%s/servicePrincipals?%s", g.baseURL(), q.Encode())

	var listResp struct {
		Value []ServicePrincipal `json:"value"`
	}
	if err := g.doJSON(ctx, token, http.MethodGet, listURL, nil, &listResp); err != nil {
		return nil, false, fmt.Errorf("lookup service principal: %w", err)
	}
	if len(listResp.Value) > 0 {
		sp := listResp.Value[0]
		return &sp, false, nil
	}

	createURL := fmt.Sprintf("%s/servicePrincipals", g.baseURL())
	var created ServicePrincipal
	if err := g.doJSON(ctx, token, http.MethodPost, createURL, map[string]any{
		"appId": appID,
	}, &created); err != nil {
		return nil, false, fmt.Errorf("create service principal: %w", err)
	}
	if created.ObjectID == "" {
		return nil, false, errors.New("graph created service principal without object id")
	}
	return &created, true, nil
}

// AddClientSecret appends a time-bounded client secret to an App Registration.
func (g *GraphClient) AddClientSecret(ctx context.Context, token, appObjectID, displayName string, startUTC, endUTC time.Time) (*PasswordCredential, error) {
	endpoint := fmt.Sprintf("%s/applications/%s/addPassword", g.baseURL(), url.PathEscape(appObjectID))
	var cred PasswordCredential
	if err := g.doJSON(ctx, token, http.MethodPost, endpoint, map[string]any{
		"passwordCredential": map[string]any{
			"displayName":   displayName,
			"startDateTime": startUTC.UTC().Format(time.RFC3339),
			"endDateTime":   endUTC.UTC().Format(time.RFC3339),
		},
	}, &cred); err != nil {
		return nil, fmt.Errorf("mint client secret: %w", err)
	}
	if cred.SecretText == "" {
		return nil, errors.New("graph returned empty client secret")
	}
	return &cred, nil
}

func trimBody(body []byte) string {
	s := strings.TrimSpace(string(body))
	if len(s) > 320 {
		return s[:320] + "..."
	}
	return s
}
