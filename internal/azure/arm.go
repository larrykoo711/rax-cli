package azure

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	CustomFreezeRoleName   = "Rax Foundry Freeze Operator"
	FallbackFreezeRoleName = "Cognitive Services Contributor"

	armSubscriptionsAPIVersion = "2022-12-01"
	armAuthAPIVersion          = "2022-04-01"

	DefaultARMRequestTimeout = 45 * time.Second
	defaultMaxRetryAttempts  = 6
)

// ReadRoles lists the 4 least-privilege read roles bound per subscription.
var ReadRoles = []string{
	"Reader",
	"Monitoring Reader",
	"Monitoring Data Reader",
	"Cost Management Reader",
}

// Well-known Azure built-in role definition GUIDs (global constants across every Azure subscription).
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

// RetryNotice describes a redacted retry event emitted during transient ARM failures.
type RetryNotice struct {
	Operation   string
	Attempt     int
	MaxAttempts int
	Reason      string
	Wait        time.Duration
}

// RequestTimeoutError distinguishes a single HTTP request timeout from overall operation deadline or cancellation.
type RequestTimeoutError struct {
	Method   string
	Endpoint string
	Timeout  time.Duration
	Cause    error
}

func (e *RequestTimeoutError) Error() string {
	return fmt.Sprintf("ARM per-request timeout after %s (%s %s): %v", e.Timeout.Round(time.Millisecond), e.Method, sanitizeEndpointForError(e.Endpoint), e.Cause)
}

func (e *RequestTimeoutError) Unwrap() error {
	return e.Cause
}

// ARMClient calls Azure Resource Manager APIs for subscription discovery and RBAC.
type ARMClient struct {
	BaseURL        string
	HTTP           *http.Client
	RequestTimeout time.Duration
	MaxRetries     int
	Sleep          func(context.Context, time.Duration) error
	OnRetry        func(RetryNotice)
}

// NewARMClient constructs an ARMClient with default management endpoint and bounded per-request timeout.
func NewARMClient(httpClient *http.Client) *ARMClient {
	if httpClient == nil {
		// Per-request timeout is enforced via context.WithTimeout in doJSON so it can be cleanly
		// distinguished from parent cancellation or overall command --timeout.
		httpClient = &http.Client{
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
				TLSHandshakeTimeout:   15 * time.Second,
				ResponseHeaderTimeout: DefaultARMRequestTimeout,
				MaxIdleConns:          32,
				MaxIdleConnsPerHost:   16,
				IdleConnTimeout:       90 * time.Second,
			},
		}
	}
	return &ARMClient{
		BaseURL:        DefaultARMBaseURL,
		HTTP:           httpClient,
		RequestTimeout: DefaultARMRequestTimeout,
		MaxRetries:     defaultMaxRetryAttempts,
		Sleep:          sleepCtx,
	}
}

func (c *ARMClient) baseURL() string {
	b := strings.TrimRight(c.BaseURL, "/")
	if b == "" {
		return DefaultARMBaseURL
	}
	return b
}

func (c *ARMClient) requestTimeout() time.Duration {
	if c.RequestTimeout > 0 {
		return c.RequestTimeout
	}
	return DefaultARMRequestTimeout
}

func (c *ARMClient) maxRetries() int {
	if c.MaxRetries > 0 {
		return c.MaxRetries
	}
	return defaultMaxRetryAttempts
}

func (c *ARMClient) sleepFn() func(context.Context, time.Duration) error {
	if c.Sleep != nil {
		return c.Sleep
	}
	return sleepCtx
}

type armHTTPError struct {
	Status     int
	URL        string
	Body       string
	RetryAfter time.Duration
}

func (e *armHTTPError) Error() string {
	return fmt.Sprintf("ARM HTTP %d (%s): %s", e.Status, sanitizeEndpointForError(e.URL), e.Body)
}

func sanitizeEndpointForError(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Scheme + "://" + u.Host + u.Path
}

func parseRetryAfterHeader(val string, now time.Time) time.Duration {
	val = strings.TrimSpace(val)
	if val == "" {
		return 0
	}
	if secs, err := strconv.Atoi(val); err == nil && secs > 0 {
		d := time.Duration(secs) * time.Second
		if d > 60*time.Second {
			return 60 * time.Second
		}
		return d
	}
	if ts, err := http.ParseTime(val); err == nil {
		d := ts.Sub(now)
		if d > 0 {
			if d > 60*time.Second {
				return 60 * time.Second
			}
			return d
		}
	}
	return 0
}

func (c *ARMClient) doJSON(ctx context.Context, token, method, endpoint string, payload any, out any) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	var bodyBytes []byte
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		bodyBytes = raw
	}

	reqTimeout := c.requestTimeout()
	reqCtx, cancel := context.WithTimeout(ctx, reqTimeout)
	defer cancel()

	var bodyReader io.Reader
	if bodyBytes != nil {
		bodyReader = bytes.NewReader(bodyBytes)
	}
	req, err := http.NewRequestWithContext(reqCtx, method, endpoint, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if bodyBytes != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		// Distinguish parent cancellation / overall deadline from per-request timeout.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if isPerRequestTimeoutErr(err, reqCtx) {
			return &RequestTimeoutError{
				Method:   method,
				Endpoint: endpoint,
				Timeout:  reqTimeout,
				Cause:    err,
			}
		}
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if isPerRequestTimeoutErr(err, reqCtx) {
			return &RequestTimeoutError{
				Method:   method,
				Endpoint: endpoint,
				Timeout:  reqTimeout,
				Cause:    err,
			}
		}
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &armHTTPError{
			Status:     resp.StatusCode,
			URL:        endpoint,
			Body:       trimBody(body),
			RetryAfter: parseRetryAfterHeader(resp.Header.Get("Retry-After"), time.Now()),
		}
	}
	if out != nil && len(body) > 0 {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("decode ARM response: %w", err)
		}
	}
	return nil
}

func isPerRequestTimeoutErr(err error, reqCtx context.Context) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(reqCtx.Err(), context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "client.timeout exceeded") || strings.Contains(msg, "timeout awaiting response headers")
}

func classifyRetryableARMError(ctx context.Context, err error) (retryable bool, reason string, retryAfter time.Duration) {
	if err == nil || ctx.Err() != nil {
		return false, "", 0
	}

	var reqTimeout *RequestTimeoutError
	if errors.As(err, &reqTimeout) {
		return true, "arm_request_timeout", 0
	}

	var httpErr *armHTTPError
	if errors.As(err, &httpErr) {
		switch httpErr.Status {
		case http.StatusTooManyRequests:
			return true, "arm_throttled_429", httpErr.RetryAfter
		case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return true, fmt.Sprintf("arm_http_%d", httpErr.Status), httpErr.RetryAfter
		case http.StatusBadRequest:
			if strings.Contains(httpErr.Body, "PrincipalNotFound") || strings.Contains(httpErr.Body, "RoleDefinitionDoesNotExist") {
				return true, "entra_replication_lag", 0
			}
			return false, "", 0
		default:
			// Never retry permanent 401/403/404/409/etc.
			return false, "", 0
		}
	}

	// Transient transport failures (EOF, connection reset, temporary net error) when parent ctx is still live.
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true, "arm_transport_eof", 0
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return true, "arm_request_timeout", 0
		}
		return true, "arm_transport_error", 0
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "connection reset") || strings.Contains(msg, "broken pipe") || strings.Contains(msg, "tls handshake timeout") {
		return true, "arm_transport_reset", 0
	}
	return false, "", 0
}

func backoffDuration(attempt int, retryAfter time.Duration) time.Duration {
	if retryAfter > 0 {
		return retryAfter
	}
	// Bounded exponential backoff: 1.5s, 3s, 6s, 10s, 15s
	schedule := []time.Duration{
		1500 * time.Millisecond,
		3 * time.Second,
		6 * time.Second,
		10 * time.Second,
		15 * time.Second,
	}
	if attempt < len(schedule) {
		return schedule[attempt]
	}
	return 15 * time.Second
}

// retryIdempotent executes an idempotent ARM operation (GET or deterministic-GUID PUT) with bounded retries.
func (c *ARMClient) retryIdempotent(ctx context.Context, opName string, fn func() error) error {
	maxAttempts := c.maxRetries()
	sleepFn := c.sleepFn()

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := fn()
		if err == nil {
			return nil
		}
		retryable, reason, retryAfter := classifyRetryableARMError(ctx, err)
		if !retryable || attempt == maxAttempts-1 {
			return err
		}
		wait := backoffDuration(attempt, retryAfter)
		if c.OnRetry != nil {
			c.OnRetry(RetryNotice{
				Operation:   opName,
				Attempt:     attempt + 1,
				MaxAttempts: maxAttempts,
				Reason:      reason,
				Wait:        wait,
			})
		}
		lastErr = err
		if sErr := sleepFn(ctx, wait); sErr != nil {
			return sErr
		}
	}
	return lastErr
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
		err := c.retryIdempotent(ctx, "list_subscriptions", func() error {
			return c.doJSON(ctx, token, http.MethodGet, nextURL, nil, &resp)
		})
		if err != nil {
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
	err := c.retryIdempotent(ctx, "find_role_definition", func() error {
		return c.doJSON(ctx, token, http.MethodGet, endpoint, nil, &resp)
	})
	if err != nil {
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
// For Azure's globally constant built-in roles, returns the canonical ID directly without an HTTP round-trip
// (saving 216+ serial ARM GET calls on a 54-subscription tenant).
func (c *ARMClient) FindRoleDefinitionID(ctx context.Context, token, subscriptionID, roleName string) (string, error) {
	if guid, ok := builtinRoleGUIDs[roleName]; ok {
		return fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s", subscriptionID, guid), nil
	}
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
	uniqueSubIDs := make([]string, 0, len(subscriptionIDs))
	seenTarget := make(map[string]bool, len(subscriptionIDs))
	for _, id := range subscriptionIDs {
		clean := strings.TrimSpace(id)
		if clean == "" {
			continue
		}
		key := strings.ToLower(clean)
		if !seenTarget[key] {
			seenTarget[key] = true
			uniqueSubIDs = append(uniqueSubIDs, clean)
			targetScopes = append(targetScopes, "/subscriptions/"+clean)
		}
	}

	// Look up whether the directory-unique custom role already exists across target subscriptions
	// using bounded concurrency (cancelling remaining probes immediately on first hit).
	existing, err := c.findCustomFreezeRoleConcurrent(ctx, token, uniqueSubIDs)
	if err != nil {
		return "", false, err
	}

	if existing != nil {
		merged, changed := mergeScopes(existing.AssignableScopes, targetScopes)
		if !changed {
			return existing.ID, false, nil
		}
		putPath := strings.TrimLeft(existing.ID, "/")
		endpoint := fmt.Sprintf("%s/%s?api-version=%s", c.baseURL(), putPath, armAuthAPIVersion)
		var updated struct {
			ID string `json:"id"`
		}
		err := c.retryIdempotent(ctx, "update_custom_freeze_role", func() error {
			return c.doJSON(ctx, token, http.MethodPut, endpoint, CustomFreezeRolePayload(merged), &updated)
		})
		if err != nil {
			return "", false, fmt.Errorf("expand custom freeze role assignableScopes (%s): %w", existing.ID, err)
		}
		if updated.ID != "" {
			return updated.ID, false, nil
		}
		return existing.ID, false, nil
	}

	// Create ONE custom role anchored to the first target subscription with all target scopes assignable.
	anchorSub := uniqueSubIDs[0]
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
	err = c.retryIdempotent(ctx, "create_custom_freeze_role", func() error {
		return c.doJSON(ctx, token, http.MethodPut, endpoint, CustomFreezeRolePayload(targetScopes), &created)
	})
	if err != nil {
		return "", false, fmt.Errorf("create custom freeze role on %s: %w", anchorSub, err)
	}
	if created.ID == "" {
		created.ID = fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s", anchorSub, roleGUID)
	}
	return created.ID, true, nil
}

func (c *ARMClient) findCustomFreezeRoleConcurrent(ctx context.Context, token string, subIDs []string) (*RoleDefinitionInfo, error) {
	if len(subIDs) == 0 {
		return nil, nil
	}
	// Fast path: check first subscription synchronously (covers the common case where anchorSub is sub[0]).
	firstInfo, err := c.FindRoleDefinition(ctx, token, subIDs[0], CustomFreezeRoleName)
	if err != nil {
		return nil, fmt.Errorf("lookup custom freeze role on %s: %w", subIDs[0], err)
	}
	if firstInfo != nil && firstInfo.ID != "" {
		return firstInfo, nil
	}
	if len(subIDs) == 1 {
		return nil, nil
	}

	probeCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	const maxWorkers = 6
	workers := maxWorkers
	if len(subIDs)-1 < workers {
		workers = len(subIDs) - 1
	}

	jobs := make(chan string, len(subIDs)-1)
	for _, id := range subIDs[1:] {
		jobs <- id
	}
	close(jobs)

	var (
		mu       sync.Mutex
		found    *RoleDefinitionInfo
		firstErr error
		wg       sync.WaitGroup
	)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for subID := range jobs {
				if probeCtx.Err() != nil {
					return
				}
				info, err := c.FindRoleDefinition(probeCtx, token, subID, CustomFreezeRoleName)
				if err != nil {
					if probeCtx.Err() != nil && ctx.Err() == nil {
						return
					}
					mu.Lock()
					if firstErr == nil {
						firstErr = fmt.Errorf("lookup custom freeze role on %s: %w", subID, err)
					}
					mu.Unlock()
					cancel()
					return
				}
				if info != nil && info.ID != "" {
					mu.Lock()
					if found == nil {
						found = info
					}
					mu.Unlock()
					cancel()
					return
				}
			}
		}()
	}
	wg.Wait()

	if found != nil {
		return found, nil
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, nil
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
// tolerating HTTP 409 RoleAssignmentExists and retrying transient ARM timeouts, HTTP 429/5xx, and
// Entra PrincipalNotFound replication lag using the exact same deterministic assignment GUID.
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

	opName := fmt.Sprintf("role_assignment(%s)", shortID(subscriptionID))
	return c.retryIdempotent(ctx, opName, func() error {
		err := c.doJSON(ctx, token, http.MethodPut, endpoint, payload, nil)
		if err == nil {
			return nil
		}
		var httpErr *armHTTPError
		if errors.As(err, &httpErr) && httpErr.Status == http.StatusConflict && strings.Contains(httpErr.Body, "RoleAssignmentExists") {
			// Idempotent success: the exact role binding already exists on ARM.
			return nil
		}
		return err
	})
}

// deterministicUUID generates a stable RFC 4122 v5-like UUID from a seed string using SHA-256.
func deterministicUUID(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	sum[6] = (sum[6] & 0x0f) | 0x50
	sum[8] = (sum[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}
