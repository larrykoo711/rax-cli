package azure

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	CustomFreezeRoleName   = "Rax Foundry Freeze Operator"
	FallbackFreezeRoleName = "Cognitive Services Contributor"

	armSubscriptionsAPIVersion = "2022-12-01"
	armAuthAPIVersion          = "2022-04-01"
)

// ReadRoles lists the 4 least-privilege read roles bound per subscription.
var ReadRoles = []string{
	"Reader",
	"Monitoring Reader",
	"Monitoring Data Reader",
	"Cost Management Reader",
}

// Well-known Azure built-in role definition GUIDs (used when roleName lookup is unneeded or as fallback).
var builtinRoleGUIDs = map[string]string{
	"Reader":                         "acdd72a7-3385-48ef-bd42-f606fba81ae7",
	"Monitoring Reader":              "43d0d8ad-25c7-4714-9337-8ba259a9fe05",
	"Monitoring Data Reader":         "b0d8363b-8ddd-447d-831f-62ca05bff136",
	"Cost Management Reader":         "72fafb9e-0641-4937-9268-a91bfd8191a3",
	"Cognitive Services Contributor": "25fbc0a9-bd7c-42a3-aa1a-3b75d497ee68",
}

// Subscription represents an Azure subscription discovered via ARM.
type Subscription struct {
	SubscriptionID string `json:"subscriptionId"`
	DisplayName    string `json:"displayName"`
	State          string `json:"state"`
	TenantID       string `json:"tenantId"`
}

// ARMClient calls Azure Resource Manager APIs for subscription discovery and RBAC.
type ARMClient struct {
	BaseURL string
	HTTP    *http.Client
	Sleep   func(context.Context, time.Duration) error
}

// NewARMClient constructs an ARMClient with default management endpoint.
func NewARMClient(httpClient *http.Client) *ARMClient {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &ARMClient{
		BaseURL: DefaultARMBaseURL,
		HTTP:    httpClient,
		Sleep:   sleepCtx,
	}
}

func (c *ARMClient) baseURL() string {
	b := strings.TrimRight(c.BaseURL, "/")
	if b == "" {
		return DefaultARMBaseURL
	}
	return b
}

type armHTTPError struct {
	Status int
	URL    string
	Body   string
}

func (e *armHTTPError) Error() string {
	return fmt.Sprintf("ARM HTTP %d (%s): %s", e.Status, e.URL, e.Body)
}

func (c *ARMClient) doJSON(ctx context.Context, token, method, endpoint string, payload any, out any) error {
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

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &armHTTPError{Status: resp.StatusCode, URL: endpoint, Body: trimBody(body)}
	}
	if out != nil && len(body) > 0 {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("decode ARM response: %w", err)
		}
	}
	return nil
}

// ListSubscriptions discovers all ARM subscriptions visible to the access token, following nextLink.
func (c *ARMClient) ListSubscriptions(ctx context.Context, token string) ([]Subscription, error) {
	nextURL := fmt.Sprintf("%s/subscriptions?api-version=%s", c.baseURL(), armSubscriptionsAPIVersion)
	var all []Subscription
	for page := 0; nextURL != "" && page < 50; page++ {
		var resp struct {
			Value    []Subscription `json:"value"`
			NextLink string         `json:"nextLink"`
		}
		if err := c.doJSON(ctx, token, http.MethodGet, nextURL, nil, &resp); err != nil {
			return nil, fmt.Errorf("list subscriptions: %w", err)
		}
		for _, sub := range resp.Value {
			if strings.TrimSpace(sub.SubscriptionID) == "" {
				continue
			}
			if strings.TrimSpace(sub.DisplayName) == "" {
				short := sub.SubscriptionID
				if len(short) > 8 {
					short = short[:8]
				}
				sub.DisplayName = "Subscription " + short
			}
			all = append(all, sub)
		}
		nextURL = strings.TrimSpace(resp.NextLink)
	}
	return all, nil
}

// CustomFreezeRolePayload builds the least-privilege ARM custom role definition payload
// permitting only publicNetworkAccess toggles while explicitly denying delete and key access.
func CustomFreezeRolePayload(subscriptionID string) map[string]any {
	return map[string]any{
		"properties": map[string]any{
			"roleName": CustomFreezeRoleName,
			"description": "Minimal write role for Rax budget guard: toggle publicNetworkAccess on " +
				"Foundry accounts without delete or key access.",
			"type": "CustomRole",
			"permissions": []map[string]any{
				{
					"actions": []string{
						"Microsoft.CognitiveServices/accounts/read",
						"Microsoft.CognitiveServices/accounts/write",
					},
					"notActions": []string{
						"Microsoft.CognitiveServices/accounts/delete",
						"Microsoft.CognitiveServices/accounts/listKeys/action",
						"Microsoft.CognitiveServices/accounts/regenerateKey/action",
					},
					"dataActions":    []string{},
					"notDataActions": []string{},
				},
			},
			"assignableScopes": []string{"/subscriptions/" + subscriptionID},
		},
	}
}

// FindRoleDefinitionID resolves the full ARM roleDefinitionId for a named role on a subscription.
func (c *ARMClient) FindRoleDefinitionID(ctx context.Context, token, subscriptionID, roleName string) (string, error) {
	escaped := strings.ReplaceAll(roleName, "'", "''")
	q := url.Values{}
	q.Set("api-version", armAuthAPIVersion)
	q.Set("$filter", fmt.Sprintf("roleName eq '%s'", escaped))
	endpoint := fmt.Sprintf(
		"%s/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions?%s",
		c.baseURL(),
		url.PathEscape(subscriptionID),
		q.Encode(),
	)

	var resp struct {
		Value []struct {
			ID string `json:"id"`
		} `json:"value"`
	}
	if err := c.doJSON(ctx, token, http.MethodGet, endpoint, nil, &resp); err != nil {
		return "", err
	}
	if len(resp.Value) > 0 && resp.Value[0].ID != "" {
		return resp.Value[0].ID, nil
	}
	if guid, ok := builtinRoleGUIDs[roleName]; ok {
		return fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s", subscriptionID, guid), nil
	}
	return "", nil
}

// EnsureCustomFreezeRole idempotently ensures the least-privilege custom freeze role exists on the subscription.
func (c *ARMClient) EnsureCustomFreezeRole(ctx context.Context, token, subscriptionID string) (string, bool, error) {
	existingID, err := c.FindRoleDefinitionID(ctx, token, subscriptionID, CustomFreezeRoleName)
	if err != nil {
		return "", false, fmt.Errorf("lookup custom freeze role on %s: %w", subscriptionID, err)
	}
	if existingID != "" {
		return existingID, false, nil
	}

	roleGUID := deterministicUUID("rax-freeze-role:" + strings.ToLower(subscriptionID))
	endpoint := fmt.Sprintf(
		"%s/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s?api-version=%s",
		c.baseURL(),
		url.PathEscape(subscriptionID),
		roleGUID,
		armAuthAPIVersion,
	)

	var created struct {
		ID string `json:"id"`
	}
	if err := c.doJSON(ctx, token, http.MethodPut, endpoint, CustomFreezeRolePayload(subscriptionID), &created); err != nil {
		return "", false, fmt.Errorf("create custom freeze role on %s: %w", subscriptionID, err)
	}
	if created.ID == "" {
		created.ID = fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s", subscriptionID, roleGUID)
	}
	return created.ID, true, nil
}

// EnsureRoleAssignment idempotently assigns a role definition to a Service Principal on a subscription,
// tolerating HTTP 409 RoleAssignmentExists and retrying transient PrincipalNotFound replication lag.
func (c *ARMClient) EnsureRoleAssignment(ctx context.Context, token, subscriptionID, spObjectID, roleDefID string) error {
	assignGUID := deterministicUUID(fmt.Sprintf("rax-assign:%s:%s:%s",
		strings.ToLower(subscriptionID),
		strings.ToLower(spObjectID),
		strings.ToLower(roleDefID),
	))
	endpoint := fmt.Sprintf(
		"%s/subscriptions/%s/providers/Microsoft.Authorization/roleAssignments/%s?api-version=%s",
		c.baseURL(),
		url.PathEscape(subscriptionID),
		assignGUID,
		armAuthAPIVersion,
	)
	payload := map[string]any{
		"properties": map[string]any{
			"roleDefinitionId": roleDefID,
			"principalId":      spObjectID,
			"principalType":    "ServicePrincipal",
		},
	}

	sleepFn := c.Sleep
	if sleepFn == nil {
		sleepFn = sleepCtx
	}

	var lastErr error
	for attempt := 0; attempt < 6; attempt++ {
		err := c.doJSON(ctx, token, http.MethodPut, endpoint, payload, nil)
		if err == nil {
			return nil
		}
		if httpErr, ok := err.(*armHTTPError); ok {
			// Idempotent success if the exact assignment already exists under another GUID.
			if httpErr.Status == http.StatusConflict && strings.Contains(httpErr.Body, "RoleAssignmentExists") {
				return nil
			}
			// Newly created Service Principals can take a few seconds to replicate to ARM.
			if httpErr.Status == http.StatusBadRequest &&
				(strings.Contains(httpErr.Body, "PrincipalNotFound") || strings.Contains(httpErr.Body, "RoleDefinitionDoesNotExist")) {
				lastErr = err
				if sErr := sleepFn(ctx, time.Duration(2+attempt*2)*time.Second); sErr != nil {
					return sErr
				}
				continue
			}
		}
		return err
	}
	return lastErr
}

// deterministicUUID generates a stable RFC 4122 v5-like UUID from a seed string using SHA-256.
func deterministicUUID(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	sum[6] = (sum[6] & 0x0f) | 0x50
	sum[8] = (sum[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}
