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
// AssignableScopes includes all target subscriptions so one tenant-wide roleName suffices.
func CustomFreezeRolePayload(assignableScopes []string) map[string]any {
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
			"assignableScopes": assignableScopes,
		},
	}
}

// RoleDefinitionInfo holds a discovered ARM role definition ID and its assignableScopes.
type RoleDefinitionInfo struct {
	ID               string
	AssignableScopes []string
}

// FindRoleDefinition looks up a role definition by exact roleName on a subscription.
func (c *ARMClient) FindRoleDefinition(ctx context.Context, token, subscriptionID, roleName string) (*RoleDefinitionInfo, error) {
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
			ID         string `json:"id"`
			Properties struct {
				AssignableScopes []string `json:"assignableScopes"`
			} `json:"properties"`
		} `json:"value"`
	}
	if err := c.doJSON(ctx, token, http.MethodGet, endpoint, nil, &resp); err != nil {
		return nil, err
	}
	if len(resp.Value) > 0 && resp.Value[0].ID != "" {
		return &RoleDefinitionInfo{
			ID:               resp.Value[0].ID,
			AssignableScopes: resp.Value[0].Properties.AssignableScopes,
		}, nil
	}
	if guid, ok := builtinRoleGUIDs[roleName]; ok {
		return &RoleDefinitionInfo{
			ID: fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s", subscriptionID, guid),
		}, nil
	}
	return nil, nil
}

// FindRoleDefinitionID resolves the full ARM roleDefinitionId for a named role on a subscription.
func (c *ARMClient) FindRoleDefinitionID(ctx context.Context, token, subscriptionID, roleName string) (string, error) {
	info, err := c.FindRoleDefinition(ctx, token, subscriptionID, roleName)
	if err != nil || info == nil {
		return "", err
	}
	return info.ID, nil
}

// EnsureCustomFreezeRoleForSubscriptions idempotently ensures ONE tenant-unique custom freeze role
// exists whose assignableScopes covers every target subscription (Microsoft Entra requires custom
// roleName uniqueness across the entire directory).
func (c *ARMClient) EnsureCustomFreezeRoleForSubscriptions(ctx context.Context, token, tenantID string, subscriptionIDs []string) (string, bool, error) {
	if len(subscriptionIDs) == 0 {
		return "", false, fmt.Errorf("at least one subscription is required for custom freeze role")
	}

	targetScopes := make([]string, 0, len(subscriptionIDs))
	seenTarget := make(map[string]bool, len(subscriptionIDs))
	for _, id := range subscriptionIDs {
		clean := strings.TrimSpace(id)
		if clean == "" {
			continue
		}
		key := strings.ToLower(clean)
		if !seenTarget[key] {
			seenTarget[key] = true
			targetScopes = append(targetScopes, "/subscriptions/"+clean)
		}
	}

	// Look up whether the directory-unique custom role already exists on any target subscription.
	var existing *RoleDefinitionInfo
	for _, subID := range subscriptionIDs {
		info, err := c.FindRoleDefinition(ctx, token, subID, CustomFreezeRoleName)
		if err != nil {
			return "", false, fmt.Errorf("lookup custom freeze role on %s: %w", subID, err)
		}
		if info != nil && info.ID != "" {
			existing = info
			break
		}
	}

	if existing != nil {
		merged, changed := mergeScopes(existing.AssignableScopes, targetScopes)
		if !changed {
			return existing.ID, false, nil
		}
		// Update existing custom role definition in place to include newly onboarded subscriptions.
		putPath := strings.TrimLeft(existing.ID, "/")
		endpoint := fmt.Sprintf("%s/%s?api-version=%s", c.baseURL(), putPath, armAuthAPIVersion)
		var updated struct {
			ID string `json:"id"`
		}
		if err := c.doJSON(ctx, token, http.MethodPut, endpoint, CustomFreezeRolePayload(merged), &updated); err != nil {
			return "", false, fmt.Errorf("expand custom freeze role assignableScopes (%s): %w", existing.ID, err)
		}
		if updated.ID != "" {
			return updated.ID, false, nil
		}
		return existing.ID, false, nil
	}

	// Create ONE custom role anchored to the first target subscription with all target scopes assignable.
	anchorSub := strings.TrimSpace(subscriptionIDs[0])
	seed := strings.ToLower(strings.TrimSpace(tenantID))
	if seed == "" {
		seed = strings.ToLower(anchorSub)
	}
	roleGUID := deterministicUUID("rax-freeze-role:" + seed)
	endpoint := fmt.Sprintf(
		"%s/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s?api-version=%s",
		c.baseURL(),
		url.PathEscape(anchorSub),
		roleGUID,
		armAuthAPIVersion,
	)

	var created struct {
		ID string `json:"id"`
	}
	if err := c.doJSON(ctx, token, http.MethodPut, endpoint, CustomFreezeRolePayload(targetScopes), &created); err != nil {
		return "", false, fmt.Errorf("create custom freeze role on %s: %w", anchorSub, err)
	}
	if created.ID == "" {
		created.ID = fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s", anchorSub, roleGUID)
	}
	return created.ID, true, nil
}

// EnsureCustomFreezeRole is a single-subscription convenience wrapper around EnsureCustomFreezeRoleForSubscriptions.
func (c *ARMClient) EnsureCustomFreezeRole(ctx context.Context, token, subscriptionID string) (string, bool, error) {
	return c.EnsureCustomFreezeRoleForSubscriptions(ctx, token, "", []string{subscriptionID})
}

func mergeScopes(existing, required []string) ([]string, bool) {
	seen := make(map[string]bool, len(existing)+len(required))
	out := make([]string, 0, len(existing)+len(required))
	for _, s := range existing {
		clean := strings.TrimSpace(s)
		if clean == "" {
			continue
		}
		k := strings.ToLower(clean)
		if !seen[k] {
			seen[k] = true
			out = append(out, clean)
		}
	}
	changed := false
	for _, s := range required {
		clean := strings.TrimSpace(s)
		if clean == "" {
			continue
		}
		k := strings.ToLower(clean)
		if !seen[k] {
			seen[k] = true
			out = append(out, clean)
			changed = true
		}
	}
	return out, changed
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
