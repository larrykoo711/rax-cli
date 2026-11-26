package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// OnboardEvent is a structured NDJSON progress event emitted when AgentMode is enabled,
// allowing AI coding agents (Claude Code, Codex, OpenCode, etc.) to parse device_code
// prompts and step transitions deterministically without scraping human prose.
type OnboardEvent struct {
	Event           string `json:"event"` // "step" | "device_code" | "done" | "error"
	Step            string `json:"step,omitempty"`
	Message         string `json:"message,omitempty"`
	VerificationURI string `json:"verificationUri,omitempty"`
	UserCode        string `json:"userCode,omitempty"`
	ExpiresIn       int    `json:"expiresIn,omitempty"`
	TenantID        string `json:"tenantId,omitempty"`
	Subscriptions   int    `json:"subscriptions,omitempty"`
	OutputPath      string `json:"outputPath,omitempty"`
}

// OnboardOptions controls the Device Code onboarding workflow.
type OnboardOptions struct {
	TenantID       string
	Slug           string
	Subscriptions  []string
	FreezeRoleMode string // "custom" (default) | "builtin"
	SecretDays     int
	Apply          bool
	OutputPath     string
	NowUTC         func() time.Time
	Log            io.Writer
	// OnEvent receives structured progress events (including device_code).
	// When set, agents can react immediately to verification_uri + user_code.
	OnEvent func(OnboardEvent)
}

// OnboardBundleSubscription describes a subscription bound during onboarding.
type OnboardBundleSubscription struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	SubscriptionID string   `json:"subscription_id"`
	Roles          []string `json:"roles"`
}

// OnboardBundle is written chmod 0600 for direct import into Rax Console.
type OnboardBundle struct {
	Schema          string                      `json:"schema"`
	TenantID        string                      `json:"tenantId"`
	Slug            string                      `json:"slug"`
	AppName         string                      `json:"appName"`
	ClientID        string                      `json:"clientId"`
	SPObjectID      string                      `json:"spObjectId"`
	ClientSecret    string                      `json:"clientSecret"`
	SecretExpiresAt string                      `json:"secretExpiresAt"`
	FreezeRoleMode  string                      `json:"freezeRoleMode"`
	Subscriptions   []OnboardBundleSubscription `json:"subscriptions"`
}

// OnboardSummary is the sanitized output returned to stdout (never contains raw secret).
type OnboardSummary struct {
	OK              bool                        `json:"ok"`
	Applied         bool                        `json:"applied"`
	Mode            string                      `json:"mode"`
	TenantID        string                      `json:"tenantId"`
	Slug            string                      `json:"slug"`
	AppName         string                      `json:"appName"`
	ClientID        string                      `json:"clientId,omitempty"`
	SPObjectID      string                      `json:"spObjectId,omitempty"`
	SecretMasked    string                      `json:"secretMasked,omitempty"`
	SecretExpiresAt string                      `json:"secretExpiresAt,omitempty"`
	FreezeRoleMode  string                      `json:"freezeRoleMode"`
	RolesPerSub     []string                    `json:"rolesPerSub"`
	Subscriptions   []OnboardBundleSubscription `json:"subscriptions"`
	OutputPath      string                      `json:"outputPath,omitempty"`
}

// Onboarder coordinates Entra Device Code auth, Graph App/SP provisioning, and ARM RBAC binding.
type Onboarder struct {
	Auth  *AuthClient
	Graph *GraphClient
	ARM   *ARMClient
}

// NewOnboarder constructs a default Onboarder backed by pure-Go HTTP clients.
func NewOnboarder() *Onboarder {
	return &Onboarder{
		Auth:  NewAuthClient(nil),
		Graph: NewGraphClient(nil),
		ARM:   NewARMClient(nil),
	}
}

// SPDisplayName returns the canonical Service Principal display name for a slug.
func SPDisplayName(slug string) string {
	s := strings.TrimSpace(slug)
	if s == "" {
		s = "azure"
	}
	if strings.HasPrefix(s, "rax-") {
		return s
	}
	return "rax-managed-sp-" + s
}

// RequiredRoles returns the exact list of RBAC role names bound per subscription.
func RequiredRoles(freezeRoleMode string) []string {
	roles := make([]string, 0, len(ReadRoles)+1)
	roles = append(roles, ReadRoles...)
	if freezeRoleMode == "builtin" {
		roles = append(roles, FallbackFreezeRoleName)
	} else {
		roles = append(roles, CustomFreezeRoleName)
	}
	return roles
}

// MaskSecret obscures all but the last 4 characters of a secret.
func MaskSecret(secret string) string {
	if len(secret) < 4 {
		return "****"
	}
	return "***" + secret[len(secret)-4:]
}

// Run executes dry-run planning or full Device Code onboarding against Azure.
func (o *Onboarder) Run(ctx context.Context, opts OnboardOptions) (*OnboardSummary, error) {
	slug := strings.TrimSpace(opts.Slug)
	if slug == "" {
		return nil, errors.New("--slug is required (e.g. --slug hailiang01)")
	}
	if opts.SecretDays == 0 {
		opts.SecretDays = 365
	}
	if opts.SecretDays < 7 || opts.SecretDays > 730 {
		return nil, fmt.Errorf("--secret-days must be between 7 and 730 (got %d)", opts.SecretDays)
	}
	freezeMode := strings.TrimSpace(opts.FreezeRoleMode)
	if freezeMode == "" {
		freezeMode = "custom"
	}
	if freezeMode != "custom" && freezeMode != "builtin" {
		return nil, fmt.Errorf("--freeze-role must be 'custom' or 'builtin' (got %q)", freezeMode)
	}

	nowFn := opts.NowUTC
	if nowFn == nil {
		nowFn = func() time.Time { return time.Now().UTC() }
	}
	logOut := opts.Log
	if logOut == nil {
		logOut = io.Discard
	}
	emit := func(ev OnboardEvent) {
		if opts.OnEvent != nil {
			opts.OnEvent(ev)
		}
	}

	appName := SPDisplayName(slug)
	roles := RequiredRoles(freezeMode)

	if !opts.Apply {
		plannedSubs := make([]OnboardBundleSubscription, 0, len(opts.Subscriptions))
		for _, id := range opts.Subscriptions {
			clean := strings.TrimSpace(id)
			if clean == "" {
				continue
			}
			plannedSubs = append(plannedSubs, OnboardBundleSubscription{
				ID:             clean,
				Name:           "Subscription " + shortID(clean),
				SubscriptionID: clean,
				Roles:          roles,
			})
		}
		return &OnboardSummary{
			OK:             true,
			Applied:        false,
			Mode:           "dry-run",
			TenantID:       strings.TrimSpace(opts.TenantID),
			Slug:           slug,
			AppName:        appName,
			FreezeRoleMode: freezeMode,
			RolesPerSub:    roles,
			Subscriptions:  plannedSubs,
			OutputPath:     opts.OutputPath,
		}, nil
	}

	// Step 1: Interactive Device Code login (zero local az CLI or Python needed; tokens stay in memory only).
	emit(OnboardEvent{Event: "step", Step: "1/5", Message: "Initiating Microsoft Entra Device Code login"})
	fmt.Fprintf(logOut, "[1/5] Initiating Microsoft Entra Device Code login...\n")
	dc, err := o.Auth.StartDeviceCode(ctx, opts.TenantID, ScopeARMUser)
	if err != nil {
		return nil, err
	}
	emit(OnboardEvent{
		Event:           "device_code",
		Step:            "1/5",
		VerificationURI: dc.VerificationURI,
		UserCode:        dc.UserCode,
		ExpiresIn:       dc.ExpiresIn,
		Message:         fmt.Sprintf("Open %s and enter code %s to sign in", dc.VerificationURI, dc.UserCode),
	})
	fmt.Fprintf(logOut, "\n  Open:  %s\n  Code:  %s\n\nWaiting for browser sign-in...\n", dc.VerificationURI, dc.UserCode)

	armTok, err := o.Auth.PollDeviceCode(ctx, opts.TenantID, dc)
	if err != nil {
		return nil, err
	}

	claims, err := ParseJWTClaims(armTok.AccessToken)
	if err != nil || claims.TenantID == "" {
		if armTok.IDToken != "" {
			claims, err = ParseJWTClaims(armTok.IDToken)
		}
	}
	if err != nil || claims == nil || claims.TenantID == "" {
		return nil, errors.New("could not resolve Entra tenant ID from sign-in token")
	}
	resolvedTenantID := claims.TenantID
	if target := strings.TrimSpace(opts.TenantID); target != "" && !strings.EqualFold(target, resolvedTenantID) {
		return nil, fmt.Errorf("tenant mismatch: signed in to %s, expected %s", resolvedTenantID, target)
	}

	// Exchange refresh token for Microsoft Graph token scoped to the resolved tenant.
	if armTok.RefreshToken == "" {
		return nil, errors.New("entra did not return a refresh_token needed for Graph API access")
	}
	graphTok, err := o.Auth.RefreshForScope(ctx, resolvedTenantID, armTok.RefreshToken, ScopeGraph)
	if err != nil {
		return nil, fmt.Errorf("acquire Microsoft Graph token: %w", err)
	}

	// Step 2: Discover enabled subscriptions under this tenant (or filter to explicit list).
	emit(OnboardEvent{Event: "step", Step: "2/5", TenantID: resolvedTenantID, Message: "Discovering enabled Azure subscriptions"})
	fmt.Fprintf(logOut, "[2/5] Signed in to tenant %s — discovering subscriptions...\n", resolvedTenantID)
	allSubs, err := o.ARM.ListSubscriptions(ctx, armTok.AccessToken)
	if err != nil {
		return nil, err
	}
	targetSubs, err := resolveTargetSubscriptions(allSubs, resolvedTenantID, opts.Subscriptions)
	if err != nil {
		return nil, err
	}
	emit(OnboardEvent{Event: "step", Step: "2/5", TenantID: resolvedTenantID, Subscriptions: len(targetSubs), Message: fmt.Sprintf("Found %d target subscription(s)", len(targetSubs))})
	fmt.Fprintf(logOut, "      Found %d target subscription(s).\n", len(targetSubs))

	// Step 3: Idempotently create single-tenant App Registration, Service Principal, and Client Secret.
	emit(OnboardEvent{Event: "step", Step: "3/5", TenantID: resolvedTenantID, Message: fmt.Sprintf("Provisioning single-tenant App & SP (%s)", appName)})
	fmt.Fprintf(logOut, "[3/5] Provisioning single-tenant App & Service Principal (%s)...\n", appName)
	app, _, err := o.Graph.EnsureApplication(ctx, graphTok.AccessToken, appName)
	if err != nil {
		return nil, err
	}
	sp, _, err := o.Graph.EnsureServicePrincipal(ctx, graphTok.AccessToken, app.AppID)
	if err != nil {
		return nil, err
	}
	now := nowFn().UTC()
	endTime := now.Add(time.Duration(opts.SecretDays) * 24 * time.Hour)
	cred, err := o.Graph.AddClientSecret(ctx, graphTok.AccessToken, app.ObjectID, "rax-managed-"+now.Format("20060102"), now, endTime)
	if err != nil {
		return nil, err
	}
	expiresAtISO := cred.EndDateTime
	if strings.TrimSpace(expiresAtISO) == "" {
		expiresAtISO = endTime.Format(time.RFC3339)
	}

	// Step 4: Bind 4 read roles + 1 freeze role per subscription.
	emit(OnboardEvent{Event: "step", Step: "4/5", TenantID: resolvedTenantID, Subscriptions: len(targetSubs), Message: "Binding least-privilege RBAC roles"})
	fmt.Fprintf(logOut, "[4/5] Binding least-privilege RBAC roles across %d subscription(s)...\n", len(targetSubs))
	assigned := make([]OnboardBundleSubscription, 0, len(targetSubs))
	for _, sub := range targetSubs {
		var freezeRoleDefID string
		var freezeRoleName string
		if freezeMode == "custom" {
			freezeRoleDefID, _, err = o.ARM.EnsureCustomFreezeRole(ctx, armTok.AccessToken, sub.SubscriptionID)
			if err != nil {
				return nil, err
			}
			freezeRoleName = CustomFreezeRoleName
		} else {
			freezeRoleDefID, err = o.ARM.FindRoleDefinitionID(ctx, armTok.AccessToken, sub.SubscriptionID, FallbackFreezeRoleName)
			if err != nil || freezeRoleDefID == "" {
				return nil, fmt.Errorf("resolve role %q on %s: %w", FallbackFreezeRoleName, sub.SubscriptionID, err)
			}
			freezeRoleName = FallbackFreezeRoleName
		}

		boundRoles := make([]string, 0, len(ReadRoles)+1)
		for _, roleName := range ReadRoles {
			roleDefID, err := o.ARM.FindRoleDefinitionID(ctx, armTok.AccessToken, sub.SubscriptionID, roleName)
			if err != nil || roleDefID == "" {
				return nil, fmt.Errorf("resolve role %q on %s: %w", roleName, sub.SubscriptionID, err)
			}
			if err := o.ARM.EnsureRoleAssignment(ctx, armTok.AccessToken, sub.SubscriptionID, sp.ObjectID, roleDefID); err != nil {
				return nil, fmt.Errorf("assign role %q on %s: %w", roleName, sub.SubscriptionID, err)
			}
			boundRoles = append(boundRoles, roleName)
		}
		if err := o.ARM.EnsureRoleAssignment(ctx, armTok.AccessToken, sub.SubscriptionID, sp.ObjectID, freezeRoleDefID); err != nil {
			return nil, fmt.Errorf("assign freeze role %q on %s: %w", freezeRoleName, sub.SubscriptionID, err)
		}
		boundRoles = append(boundRoles, freezeRoleName)

		assigned = append(assigned, OnboardBundleSubscription{
			ID:             sub.SubscriptionID,
			Name:           sub.DisplayName,
			SubscriptionID: sub.SubscriptionID,
			Roles:          boundRoles,
		})
	}

	// Step 5: Write chmod-600 bundle file for direct Rax Console import.
	bundle := OnboardBundle{
		Schema:          "rax-azure-tenant-bundle/v1",
		TenantID:        resolvedTenantID,
		Slug:            slug,
		AppName:         appName,
		ClientID:        app.AppID,
		SPObjectID:      sp.ObjectID,
		ClientSecret:    cred.SecretText,
		SecretExpiresAt: expiresAtISO,
		FreezeRoleMode:  freezeMode,
		Subscriptions:   assigned,
	}

	outPath := strings.TrimSpace(opts.OutputPath)
	if outPath != "" {
		if err := writeSecureBundle(outPath, bundle); err != nil {
			return nil, err
		}
		emit(OnboardEvent{Event: "step", Step: "5/5", OutputPath: outPath, Message: "Wrote chmod-600 onboarding bundle"})
		fmt.Fprintf(logOut, "[5/5] Wrote chmod-600 onboarding bundle to %s\n", outPath)
	} else {
		fmt.Fprintf(logOut, "[5/5] Provisioning complete.\n")
	}

	return &OnboardSummary{
		OK:              true,
		Applied:         true,
		Mode:            "apply",
		TenantID:        resolvedTenantID,
		Slug:            slug,
		AppName:         appName,
		ClientID:        app.AppID,
		SPObjectID:      sp.ObjectID,
		SecretMasked:    MaskSecret(cred.SecretText),
		SecretExpiresAt: expiresAtISO,
		FreezeRoleMode:  freezeMode,
		RolesPerSub:     roles,
		Subscriptions:   assigned,
		OutputPath:      outPath,
	}, nil
}

func resolveTargetSubscriptions(all []Subscription, tenantID string, explicit []string) ([]Subscription, error) {
	byID := make(map[string]Subscription, len(all))
	for _, s := range all {
		byID[strings.ToLower(s.SubscriptionID)] = s
	}

	if len(explicit) > 0 {
		out := make([]Subscription, 0, len(explicit))
		for _, raw := range explicit {
			id := strings.TrimSpace(raw)
			if id == "" {
				continue
			}
			if found, ok := byID[strings.ToLower(id)]; ok {
				out = append(out, found)
			} else {
				out = append(out, Subscription{
					SubscriptionID: id,
					DisplayName:    "Subscription " + shortID(id),
					State:          "Enabled",
					TenantID:       tenantID,
				})
			}
		}
		if len(out) == 0 {
			return nil, errors.New("no valid subscription IDs specified")
		}
		return out, nil
	}

	var out []Subscription
	for _, s := range all {
		if !strings.EqualFold(s.State, "Enabled") {
			continue
		}
		if s.TenantID != "" && !strings.EqualFold(s.TenantID, tenantID) {
			continue
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no enabled Azure subscriptions found under tenant %s", tenantID)
	}
	return out, nil
}

func writeSecureBundle(path string, bundle OnboardBundle) error {
	raw, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create output directory: %w", err)
		}
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("write bundle file: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod 600 bundle file: %w", err)
	}
	return nil
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
