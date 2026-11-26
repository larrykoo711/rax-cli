package azure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AzureCLIClientID is Microsoft's first-party public client ID used by Azure CLI
// for interactive Device Code authentication across Entra tenants without requiring
// pre-registered apps or local az installation.
const AzureCLIClientID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

const (
	DefaultLoginBaseURL = "https://login.microsoftonline.com"
	DefaultGraphBaseURL = "https://graph.microsoft.com/v1.0"
	DefaultARMBaseURL   = "https://management.azure.com"

	ScopeARMUser    = "https://management.azure.com/user_impersonation offline_access openid profile"
	ScopeARMDefault = "https://management.azure.com/.default offline_access"
	ScopeGraph      = "https://graph.microsoft.com/.default offline_access"
	ScopeARMApp     = "https://management.azure.com/.default"
	ScopeMonitorApp = "https://metrics.monitor.azure.com/.default"
)

// AuthClient performs Microsoft Entra OAuth 2.0 Device Code and Client Credentials flows.
type AuthClient struct {
	LoginBaseURL string
	ClientID     string
	HTTP         *http.Client
	Sleep        func(context.Context, time.Duration) error
}

// DeviceCodeResponse holds the user-facing code and verification URL.
type DeviceCodeResponse struct {
	UserCode        string `json:"user_code"`
	DeviceCode      string `json:"device_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Message         string `json:"message"`
}

// TokenResponse holds OAuth tokens returned by Entra ID.
type TokenResponse struct {
	TokenType    string `json:"token_type"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
}

type oauthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// NewAuthClient constructs an AuthClient with safe defaults.
func NewAuthClient(httpClient *http.Client) *AuthClient {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &AuthClient{
		LoginBaseURL: DefaultLoginBaseURL,
		ClientID:     AzureCLIClientID,
		HTTP:         httpClient,
		Sleep:        sleepCtx,
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (a *AuthClient) baseURL() string {
	b := strings.TrimRight(a.LoginBaseURL, "/")
	if b == "" {
		return DefaultLoginBaseURL
	}
	return b
}

func (a *AuthClient) clientID() string {
	if a.ClientID == "" {
		return AzureCLIClientID
	}
	return a.ClientID
}

// StartDeviceCode initiates an OAuth 2.0 Device Authorization Grant for the given tenant
// (pass "" or "organizations" to auto-detect the signed-in user's Entra tenant).
func (a *AuthClient) StartDeviceCode(ctx context.Context, tenant, scope string) (*DeviceCodeResponse, error) {
	authority := strings.TrimSpace(tenant)
	if authority == "" {
		authority = "organizations"
	}
	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/devicecode", a.baseURL(), url.PathEscape(authority))
	form := url.Values{}
	form.Set("client_id", a.clientID())
	form.Set("scope", scope)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request device code: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device code request failed (HTTP %d): %s", resp.StatusCode, extractOAuthErr(body))
	}

	var dc DeviceCodeResponse
	if err := json.Unmarshal(body, &dc); err != nil {
		return nil, fmt.Errorf("decode device code response: %w", err)
	}
	if dc.DeviceCode == "" || dc.UserCode == "" {
		return nil, errors.New("entra returned incomplete device code payload")
	}
	if dc.Interval <= 0 {
		dc.Interval = 5
	}
	return &dc, nil
}

// PollDeviceCode polls Entra's token endpoint until the user completes browser sign-in
// or the device code expires.
func (a *AuthClient) PollDeviceCode(ctx context.Context, tenant string, dc *DeviceCodeResponse) (*TokenResponse, error) {
	authority := strings.TrimSpace(tenant)
	if authority == "" {
		authority = "organizations"
	}
	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token", a.baseURL(), url.PathEscape(authority))
	interval := time.Duration(dc.Interval) * time.Second
	deadline := time.Now().Add(time.Duration(dc.ExpiresIn) * time.Second)
	if dc.ExpiresIn <= 0 {
		deadline = time.Now().Add(15 * time.Minute)
	}

	sleepFn := a.Sleep
	if sleepFn == nil {
		sleepFn = sleepCtx
	}

	for {
		if time.Now().After(deadline) {
			return nil, errors.New("device code expired before sign-in completed")
		}
		if err := sleepFn(ctx, interval); err != nil {
			return nil, err
		}

		form := url.Values{}
		form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		form.Set("client_id", a.clientID())
		form.Set("device_code", dc.DeviceCode)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := a.HTTP.Do(req)
		if err != nil {
			return nil, fmt.Errorf("poll device code token: %w", err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == http.StatusOK {
			var tok TokenResponse
			if err := json.Unmarshal(body, &tok); err != nil {
				return nil, fmt.Errorf("decode token response: %w", err)
			}
			return &tok, nil
		}

		var oe oauthErrorResponse
		_ = json.Unmarshal(body, &oe)
		switch oe.Error {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		case "expired_token":
			return nil, errors.New("device code expired; please re-run the command")
		case "authorization_declined":
			return nil, errors.New("sign-in was declined in the browser")
		default:
			return nil, fmt.Errorf("device code token failed (HTTP %d): %s", resp.StatusCode, extractOAuthErr(body))
		}
	}
}

// RefreshForScope exchanges a refresh token for an access token targeting another resource scope
// (e.g. Microsoft Graph after ARM sign-in) inside the resolved Entra tenant.
func (a *AuthClient) RefreshForScope(ctx context.Context, tenantID, refreshToken, scope string) (*TokenResponse, error) {
	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token", a.baseURL(), url.PathEscape(tenantID))
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", a.clientID())
	form.Set("refresh_token", refreshToken)
	form.Set("scope", scope)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("refresh token for %s: %w", scope, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("refresh token failed (HTTP %d): %s", resp.StatusCode, extractOAuthErr(body))
	}

	var tok TokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("decode refreshed token: %w", err)
	}
	return &tok, nil
}

// FetchServicePrincipalToken mints an OAuth 2.0 client_credentials token for an Azure SP.
func (a *AuthClient) FetchServicePrincipalToken(ctx context.Context, tenantID, clientID, clientSecret, scope string) (*TokenResponse, error) {
	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token", a.baseURL(), url.PathEscape(tenantID))
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("scope", scope)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client_credentials token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client_credentials token failed (HTTP %d): %s", resp.StatusCode, extractOAuthErr(body))
	}

	var tok TokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("decode client_credentials token: %w", err)
	}
	return &tok, nil
}

// JWTClaims holds minimal unsigned claims parsed from an Entra access/id JWT for tenant verification.
type JWTClaims struct {
	TenantID          string `json:"tid"`
	UPN               string `json:"upn"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
}

// ParseJWTClaims decodes the payload segment of a JWT without re-verifying its signature
// (used solely for extracting tid/upn from a token freshly received over TLS from Entra).
func ParseJWTClaims(jwtToken string) (*JWTClaims, error) {
	parts := strings.Split(jwtToken, ".")
	if len(parts) < 2 {
		return nil, errors.New("invalid JWT format")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWT payload: %w", err)
	}
	var claims JWTClaims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal JWT claims: %w", err)
	}
	return &claims, nil
}

func extractOAuthErr(body []byte) string {
	var oe oauthErrorResponse
	if err := json.Unmarshal(body, &oe); err == nil && (oe.Error != "" || oe.ErrorDescription != "") {
		desc := strings.SplitN(oe.ErrorDescription, "\r\n", 2)[0]
		if desc != "" {
			return fmt.Sprintf("%s: %s", oe.Error, desc)
		}
		return oe.Error
	}
	s := strings.TrimSpace(string(body))
	if len(s) > 240 {
		s = s[:240]
	}
	return s
}
