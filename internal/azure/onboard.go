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
	"sync"
	"time"
)

// OnboardEvent is a structured NDJSON progress event emitted when AgentMode is enabled,
// allowing AI coding agents (Claude Code, Codex, OpenCode, etc.) to parse device_code
// prompts, per-subscription progress, retries, and failures deterministically.
type OnboardEvent struct {
	Event             string `json:"event"` // "step" | "device_code" | "progress" | "retry" | "done" | "error"
	Step              string `json:"step,omitempty"`
	Message           string `json:"message,omitempty"`
	VerificationURI   string `json:"verificationUri,omitempty"`
	UserCode          string `json:"userCode,omitempty"`
	ExpiresIn         int    `json:"expiresIn,omitempty"`
	TenantID          string `json:"tenantId,omitempty"`
	Subscriptions     int    `json:"subscriptions,omitempty"`
	Completed         int    `json:"completed,omitempty"`
	Total             int    `json:"total,omitempty"`
	SubscriptionID    string `json:"subscriptionId,omitempty"`
	SubscriptionName  string `json:"subscriptionName,omitempty"`
	Attempt           int    `json:"attempt,omitempty"`
	MaxAttempts       int    `json:"maxAttempts,omitempty"`
	Reason            string `json:"reason,omitempty"`
	RetryAfterSeconds int    `json:"retryAfterSeconds,omitempty"`
	OutputPath        string `json:"outputPath,omitempty"`
}

// OnboardFailureError wraps an onboarding error with deterministic progress accounting
// and timeout classification so operators and AI agents know what completed and whether
// secret creation started (safe idempotent resume).
type OnboardFailureError struct {
	Step          string
	Completed     int
	Total         int
	Pending       int
	SecretCreated bool
	Resumable     bool
	TimeoutKind   string // "device_code" | "request" | "overall" | ""
	Cause         error
}

func (e *OnboardFailureError) Error() string {
	var parts []string
	if e.Step != "" {
		parts = append(parts, "step "+e.Step)
	}
	if e.Total > 0 {
		parts = append(parts, fmt.Sprintf("completed %d/%d subscriptions (%d pending)", e.Completed, e.Total, e.Pending))
	}
	if !e.SecretCreated {
		parts = append(parts, "secretCreated=false")
	} else {
		parts = append(parts, "secretCreated=true")
	}
	if e.TimeoutKind != "" {
		parts = append(parts, "timeout="+e.TimeoutKind)
	}
	return fmt.Sprintf("%s [%s]", e.Cause.Error(), strings.Join(parts, ", "))
}

func (e *OnboardFailureError) Unwrap() error {
	return e.Cause
}

// OnboardOptions controls the Device Code onboarding workflow.
type OnboardOptions struct {
	TenantID         string
	Slug             string
	Subscriptions    []string
	FreezeRoleMode   string // "custom" (default) | "builtin"
	SecretDays       int
	Apply            bool
	Concurrency      int // Bounded parallel subscription RBAC workers (default 4, max 8)
	OutputPath       string
	PlainOutput      bool // Opt-in plaintext export for local debugging; default writes RSA-OAEP+AES-256-GCM sealed bundle.
	SealKeyID        string
	SealPublicKeyPEM string
	NowUTC           func() time.Time
	Log              io.Writer
	// OnEvent receives structured progress events (including device_code, progress, retry).
	// When set, agents can react immediately to verification_uri + user_code and monitor multi-sub progress.
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
	Schema            string                      `json:"schema"`
	TenantID          string                      `json:"tenantId"`
	Slug              string                      `json:"slug"`
	AppName           string                      `json:"appName"`
	TenantDisplayName string                      `json:"tenantDisplayName,omitempty"`
	TenantDomain      string                      `json:"tenantDomain,omitempty"`
	AuthorizedByEmail string                      `json:"authorizedByEmail,omitempty"`
	ClientID          string                      `json:"clientId"`
	SPObjectID        string                      `json:"spObjectId"`
	ClientSecret      string                      `json:"clientSecret"`
	SecretExpiresAt   string                      `json:"secretExpiresAt"`
	FreezeRoleMode    string                      `json:"freezeRoleMode"`
	Subscriptions     []OnboardBundleSubscription `json:"subscriptions"`
}

// OnboardSummary is the sanitized output returned to stdout (never contains raw secret).
type OnboardSummary struct {
	OK                bool                        `json:"ok"`
	Applied           bool                        `json:"applied"`
	Mode              string                      `json:"mode"`
	Sealed            bool                        `json:"sealed"`
	KeyID             string                      `json:"keyId,omitempty"`
	Verified          bool                        `json:"verified"`
	TenantID          string                      `json:"tenantId"`
	Slug              string                      `json:"slug"`
	AppName           string                      `json:"appName"`
	TenantDisplayName string                      `json:"tenantDisplayName,omitempty"`
	TenantDomain      string                      `json:"tenantDomain,omitempty"`
	AuthorizedByEmail string                      `json:"authorizedByEmail,omitempty"`
	ClientID          string                      `json:"clientId,omitempty"`
	SPObjectID        string                      `json:"spObjectId,omitempty"`
	SecretMasked      string                      `json:"secretMasked,omitempty"`
	SecretExpiresAt   string                      `json:"secretExpiresAt,omitempty"`
	FreezeRoleMode    string                      `json:"freezeRoleMode"`
	RolesPerSub       []string                    `json:"rolesPerSub"`
	Subscriptions     []OnboardBundleSubscription `json:"subscriptions"`
	OutputPath        string                      `json:"outputPath,omitempty"`
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

func classifyTimeoutKind(ctx context.Context, err error, step string) string {
	if err == nil {
		return ""
	}
	var reqTimeout *RequestTimeoutError
	if errors.As(err, &reqTimeout) {
		return "request"
	}
	msg := strings.ToLower(err.Error())
	if step == "1/5" && (strings.Contains(msg, "device code expired") || strings.Contains(msg, "expired_token")) {
		return "device_code"
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "overall"
	}
	if strings.Contains(msg, "per-request timeout") || strings.Contains(msg, "client.timeout exceeded") {
		return "request"
	}
	return ""
}

// Run executes dry-run planning or full Device Code onboarding against Azure.
func (o *Onboarder) Run(ctx context.Context, opts OnboardOptions) (*OnboardSummary, error) {
	explicitSlug := strings.TrimSpace(opts.Slug)
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
	var emitMu sync.Mutex
	emit := func(ev OnboardEvent) {
		if opts.OnEvent != nil {
			emitMu.Lock()
			opts.OnEvent(ev)
			emitMu.Unlock()
		}
	}
	logf := func(format string, args ...any) {
		emitMu.Lock()
		fmt.Fprintf(logOut, format, args...)
		emitMu.Unlock()
	}

	roles := RequiredRoles(freezeMode)

	if !opts.Apply {
		previewSlug := explicitSlug
		previewAppName := "rax-managed-sp-<auto-from-domain>"
		if previewSlug != "" {
			previewAppName = SPDisplayName(previewSlug)
		} else {
			previewSlug = "auto"
		}
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
		plannedOut := ResolveOutputPath(opts.OutputPath, previewSlug, nowFn().UTC(), opts.PlainOutput)
		return &OnboardSummary{
			OK:             true,
			Applied:        false,
			Mode:           "dry-run",
			Sealed:         !opts.PlainOutput,
			KeyID:          effectiveKeyID(opts.SealKeyID, opts.PlainOutput),
			TenantID:       strings.TrimSpace(opts.TenantID),
			Slug:           previewSlug,
			AppName:        previewAppName,
			FreezeRoleMode: freezeMode,
			RolesPerSub:    roles,
			Subscriptions:  plannedSubs,
			OutputPath:     plannedOut,
		}, nil
	}

	// Hook redacted ARM retry telemetry into OnEvent & human logs for the duration of this run.
	currentStep := "1/5"
	prevOnRetry := o.ARM.OnRetry
	o.ARM.OnRetry = func(n RetryNotice) {
		if prevOnRetry != nil {
			prevOnRetry(n)
		}
		waitSecs := int(n.Wait.Round(time.Second) / time.Second)
		if waitSecs < 1 {
			waitSecs = 1
		}
		emit(OnboardEvent{
			Event:             "retry",
			Step:              currentStep,
			Attempt:           n.Attempt,
			MaxAttempts:       n.MaxAttempts,
			Reason:            n.Reason,
			RetryAfterSeconds: waitSecs,
			Message:           fmt.Sprintf("Retrying %s (%d/%d) after %ds due to %s", n.Operation, n.Attempt, n.MaxAttempts, waitSecs, n.Reason),
		})
		logf("      [retry %d/%d] %s (%s) — waiting %ds...\n", n.Attempt, n.MaxAttempts, n.Operation, n.Reason, waitSecs)
	}
	defer func() {
		o.ARM.OnRetry = prevOnRetry
	}()

	wrapFail := func(step string, completed, total int, secretCreated bool, err error) error {
		pending := total - completed
		if pending < 0 {
			pending = 0
		}
		return &OnboardFailureError{
			Step:          step,
			Completed:     completed,
			Total:         total,
			Pending:       pending,
			SecretCreated: secretCreated,
			Resumable:     true,
			TimeoutKind:   classifyTimeoutKind(ctx, err, step),
			Cause:         err,
		}
	}

	// Step 1: Interactive Device Code login (zero local az CLI or Python needed; tokens stay in memory only).
	emit(OnboardEvent{Event: "step", Step: "1/5", Message: "Initiating Microsoft Entra Device Code login"})
	logf("[1/5] Initiating Microsoft Entra Device Code login...\n")
	dc, err := o.Auth.StartDeviceCode(ctx, opts.TenantID, ScopeARMUser)
	if err != nil {
		return nil, wrapFail("1/5", 0, 0, false, err)
	}
	emit(OnboardEvent{
		Event:           "device_code",
		Step:            "1/5",
		VerificationURI: dc.VerificationURI,
		UserCode:        dc.UserCode,
		ExpiresIn:       dc.ExpiresIn,
		Message:         fmt.Sprintf("Open %s and enter code %s to sign in", dc.VerificationURI, dc.UserCode),
	})
	logf("\n  Open:  %s\n  Code:  %s\n\nWaiting for browser sign-in...\n", dc.VerificationURI, dc.UserCode)

	armTok, err := o.Auth.PollDeviceCode(ctx, opts.TenantID, dc)
	if err != nil {
		return nil, wrapFail("1/5", 0, 0, false, err)
	}

	claims, err := ParseJWTClaims(armTok.AccessToken)
	if err != nil || claims.TenantID == "" {
		if armTok.IDToken != "" {
			claims, err = ParseJWTClaims(armTok.IDToken)
		}
	}
	if err != nil || claims == nil || claims.TenantID == "" {
		return nil, wrapFail("1/5", 0, 0, false, errors.New("could not resolve Entra tenant ID from sign-in token"))
	}
	resolvedTenantID := claims.TenantID
	if target := strings.TrimSpace(opts.TenantID); target != "" && !strings.EqualFold(target, resolvedTenantID) {
		return nil, wrapFail("1/5", 0, 0, false, fmt.Errorf("tenant mismatch: signed in to %s, expected %s", resolvedTenantID, target))
	}

	// Exchange refresh token for Microsoft Graph token scoped to the resolved tenant.
	if armTok.RefreshToken == "" {
		return nil, wrapFail("1/5", 0, 0, false, errors.New("entra did not return a refresh_token needed for Graph API access"))
	}
	graphTok, err := o.Auth.RefreshForScope(ctx, resolvedTenantID, armTok.RefreshToken, ScopeGraph)
	if err != nil {
		return nil, wrapFail("1/5", 0, 0, false, fmt.Errorf("acquire Microsoft Graph token: %w", err))
	}

	// Resolve signed-in admin email and tenant *.onmicrosoft.com domain to auto-derive slug when omitted.
	authorizedEmail := claims.ResolvedEmail()
	if authorizedEmail == "" && armTok.IDToken != "" {
		if idClaims, idErr := ParseJWTClaims(armTok.IDToken); idErr == nil {
			authorizedEmail = idClaims.ResolvedEmail()
		}
	}
	if authorizedEmail == "" {
		if gClaims, gErr := ParseJWTClaims(graphTok.AccessToken); gErr == nil {
			authorizedEmail = gClaims.ResolvedEmail()
		}
	}

	orgInfo, _ := o.Graph.GetOrganizationInfo(ctx, graphTok.AccessToken)
	autoSlug, tenantDomain := DeriveTenantSlug(orgInfo, authorizedEmail, resolvedTenantID)
	slug := explicitSlug
	if slug == "" {
		slug = autoSlug
	}
	appName := SPDisplayName(slug)
	tenantDisplayName := ""
	if orgInfo != nil && orgInfo.DisplayName != "" {
		tenantDisplayName = orgInfo.DisplayName
	}

	// Step 2: Discover enabled subscriptions under this tenant (or filter to explicit list).
	currentStep = "2/5"
	emit(OnboardEvent{Event: "step", Step: "2/5", TenantID: resolvedTenantID, Message: "Discovering enabled Azure subscriptions"})
	logf("[2/5] Signed in to tenant %s — discovering subscriptions...\n", resolvedTenantID)
	allSubs, err := o.ARM.ListSubscriptions(ctx, armTok.AccessToken)
	if err != nil {
		return nil, wrapFail("2/5", 0, 0, false, err)
	}
	targetSubs, err := resolveTargetSubscriptions(allSubs, resolvedTenantID, opts.Subscriptions)
	if err != nil {
		return nil, wrapFail("2/5", 0, 0, false, err)
	}
	totalSubs := len(targetSubs)
	emit(OnboardEvent{Event: "step", Step: "2/5", TenantID: resolvedTenantID, Subscriptions: totalSubs, Total: totalSubs, Message: fmt.Sprintf("Found %d target subscription(s)", totalSubs)})
	logf("      Found %d target subscription(s).\n", totalSubs)

	// Step 3: Idempotently create single-tenant App Registration & Service Principal (no secret minted yet).
	currentStep = "3/5"
	emit(OnboardEvent{Event: "step", Step: "3/5", TenantID: resolvedTenantID, Total: totalSubs, Message: fmt.Sprintf("Provisioning single-tenant App & SP (%s)", appName)})
	logf("[3/5] Provisioning single-tenant App & Service Principal (%s)...\n", appName)
	app, _, err := o.Graph.EnsureApplication(ctx, graphTok.AccessToken, appName)
	if err != nil {
		return nil, wrapFail("3/5", 0, totalSubs, false, err)
	}
	sp, _, err := o.Graph.EnsureServicePrincipal(ctx, graphTok.AccessToken, app.AppID)
	if err != nil {
		return nil, wrapFail("3/5", 0, totalSubs, false, err)
	}

	// Step 4: Ensure ONE tenant-unique custom freeze role covering all target subscriptions,
	// then bind 4 read roles + 1 freeze role per subscription with bounded concurrency BEFORE minting any Client Secret.
	currentStep = "4/5"
	emit(OnboardEvent{Event: "step", Step: "4/5", TenantID: resolvedTenantID, Subscriptions: totalSubs, Completed: 0, Total: totalSubs, Message: fmt.Sprintf("Binding least-privilege RBAC roles across %d subscription(s)", totalSubs)})
	logf("[4/5] Binding least-privilege RBAC roles across %d subscription(s)...\n", totalSubs)
	targetSubIDs := make([]string, 0, totalSubs)
	for _, sub := range targetSubs {
		targetSubIDs = append(targetSubIDs, sub.SubscriptionID)
	}

	var sharedCustomFreezeRoleID string
	if freezeMode == "custom" {
		sharedCustomFreezeRoleID, _, err = o.ARM.EnsureCustomFreezeRoleForSubscriptions(ctx, armTok.AccessToken, resolvedTenantID, targetSubIDs)
		if err != nil {
			return nil, wrapFail("4/5", 0, totalSubs, false, err)
		}
	}

	workers := opts.Concurrency
	if workers <= 0 {
		workers = 4
	}
	if workers > 8 {
		workers = 8
	}
	if totalSubs < workers {
		workers = totalSubs
	}

	type subJob struct {
		index int
		sub   Subscription
	}
	results := make([]OnboardBundleSubscription, totalSubs)
	completedFlags := make([]bool, totalSubs)

	bindCtx, cancelBind := context.WithCancel(ctx)
	defer cancelBind()

	jobs := make(chan subJob, totalSubs)
	for idx, sub := range targetSubs {
		jobs <- subJob{index: idx, sub: sub}
	}
	close(jobs)

	var (
		stateMu        sync.Mutex
		completedCount int
		firstBindErr   error
		wg             sync.WaitGroup
	)

	bindOne := func(sub Subscription) (OnboardBundleSubscription, error) {
		var freezeRoleDefID string
		var freezeRoleName string
		if freezeMode == "custom" {
			freezeRoleDefID = sharedCustomFreezeRoleID
			freezeRoleName = CustomFreezeRoleName
		} else {
			defID, rErr := o.ARM.FindRoleDefinitionID(bindCtx, armTok.AccessToken, sub.SubscriptionID, FallbackFreezeRoleName)
			if rErr != nil || defID == "" {
				return OnboardBundleSubscription{}, fmt.Errorf("resolve role %q on %s: %w", FallbackFreezeRoleName, sub.SubscriptionID, rErr)
			}
			freezeRoleDefID = defID
			freezeRoleName = FallbackFreezeRoleName
		}

		boundRoles := make([]string, 0, len(ReadRoles)+1)
		for _, roleName := range ReadRoles {
			roleDefID, rErr := o.ARM.FindRoleDefinitionID(bindCtx, armTok.AccessToken, sub.SubscriptionID, roleName)
			if rErr != nil || roleDefID == "" {
				return OnboardBundleSubscription{}, fmt.Errorf("resolve role %q on %s: %w", roleName, sub.SubscriptionID, rErr)
			}
			if aErr := o.ARM.EnsureRoleAssignment(bindCtx, armTok.AccessToken, sub.SubscriptionID, sp.ObjectID, roleDefID); aErr != nil {
				return OnboardBundleSubscription{}, fmt.Errorf("assign role %q on %s: %w", roleName, sub.SubscriptionID, aErr)
			}
			boundRoles = append(boundRoles, roleName)
		}
		if aErr := o.ARM.EnsureRoleAssignment(bindCtx, armTok.AccessToken, sub.SubscriptionID, sp.ObjectID, freezeRoleDefID); aErr != nil {
			return OnboardBundleSubscription{}, fmt.Errorf("assign freeze role %q on %s: %w", freezeRoleName, sub.SubscriptionID, aErr)
		}
		boundRoles = append(boundRoles, freezeRoleName)

		return OnboardBundleSubscription{
			ID:             sub.SubscriptionID,
			Name:           sub.DisplayName,
			SubscriptionID: sub.SubscriptionID,
			Roles:          boundRoles,
		}, nil
	}

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if bindCtx.Err() != nil {
					return
				}
				entry, bErr := bindOne(job.sub)
				if bErr != nil {
					stateMu.Lock()
					if firstBindErr == nil {
						firstBindErr = bErr
					}
					stateMu.Unlock()
					cancelBind()
					return
				}
				stateMu.Lock()
				results[job.index] = entry
				completedFlags[job.index] = true
				completedCount++
				doneNow := completedCount
				stateMu.Unlock()

				emit(OnboardEvent{
					Event:            "progress",
					Step:             "4/5",
					TenantID:         resolvedTenantID,
					Completed:        doneNow,
					Total:            totalSubs,
					SubscriptionID:   job.sub.SubscriptionID,
					SubscriptionName: job.sub.DisplayName,
					Message:          fmt.Sprintf("Bound RBAC roles (%d/%d): %s", doneNow, totalSubs, job.sub.DisplayName),
				})
				logf("      [%d/%d] Bound %d roles on %s (%s)\n", doneNow, totalSubs, len(entry.Roles), job.sub.DisplayName, shortID(job.sub.SubscriptionID))
			}
		}()
	}
	wg.Wait()

	if firstBindErr != nil {
		return nil, wrapFail("4/5", completedCount, totalSubs, false, firstBindErr)
	}
	if ctx.Err() != nil {
		return nil, wrapFail("4/5", completedCount, totalSubs, false, ctx.Err())
	}

	assigned := make([]OnboardBundleSubscription, 0, totalSubs)
	for i := 0; i < totalSubs; i++ {
		if completedFlags[i] {
			assigned = append(assigned, results[i])
		}
	}

	// Step 5: Only after all RBAC bindings succeed, mint Client Secret, self-verify in memory,
	// seal with Rax platform RSA-2048 public key, and write to ~/Downloads/rax-cli/.
	currentStep = "5/5"
	now := nowFn().UTC()
	endTime := now.Add(time.Duration(opts.SecretDays) * 24 * time.Hour)
	cred, err := o.Graph.AddClientSecret(ctx, graphTok.AccessToken, app.ObjectID, "rax-managed-"+now.Format("20060102"), now, endTime)
	if err != nil {
		return nil, wrapFail("5/5", totalSubs, totalSubs, false, err)
	}
	expiresAtISO := cred.EndDateTime
	if strings.TrimSpace(expiresAtISO) == "" {
		expiresAtISO = endTime.Format(time.RFC3339)
	}

	verified := false
	if vRes, vErr := o.Verify(ctx, VerifyCredentials{
		TenantID:     resolvedTenantID,
		ClientID:     app.AppID,
		ClientSecret: cred.SecretText,
	}); vErr == nil && vRes != nil && vRes.OK {
		verified = true
	}

	bundle := OnboardBundle{
		Schema:            "rax-azure-tenant-bundle/v1",
		TenantID:          resolvedTenantID,
		Slug:              slug,
		AppName:           appName,
		TenantDisplayName: tenantDisplayName,
		TenantDomain:      tenantDomain,
		AuthorizedByEmail: authorizedEmail,
		ClientID:          app.AppID,
		SPObjectID:        sp.ObjectID,
		ClientSecret:      cred.SecretText,
		SecretExpiresAt:   expiresAtISO,
		FreezeRoleMode:    freezeMode,
		Subscriptions:     assigned,
	}

	outPath := ResolveOutputPath(opts.OutputPath, slug, now, opts.PlainOutput)
	sealedMode := !opts.PlainOutput
	keyID := effectiveKeyID(opts.SealKeyID, opts.PlainOutput)

	if sealedMode {
		sealedDoc, err := SealBundle(bundle, verified, now, keyID, opts.SealPublicKeyPEM)
		if err != nil {
			return nil, wrapFail("5/5", totalSubs, totalSubs, true, fmt.Errorf("seal onboarding bundle: %w", err))
		}
		if err := writeSecureJSON(outPath, sealedDoc); err != nil {
			return nil, wrapFail("5/5", totalSubs, totalSubs, true, err)
		}
		emit(OnboardEvent{Event: "step", Step: "5/5", Completed: totalSubs, Total: totalSubs, OutputPath: outPath, Message: "Wrote RSA-OAEP+AES-256-GCM sealed onboarding bundle"})
		logf("[5/5] Wrote encrypted bundle (only Rax Console can decrypt) to %s\n", outPath)
	} else {
		if err := writeSecureJSON(outPath, bundle); err != nil {
			return nil, wrapFail("5/5", totalSubs, totalSubs, true, err)
		}
		emit(OnboardEvent{Event: "step", Step: "5/5", Completed: totalSubs, Total: totalSubs, OutputPath: outPath, Message: "Wrote chmod-600 plaintext onboarding bundle"})
		logf("[5/5] Wrote chmod-600 plaintext bundle to %s\n", outPath)
	}

	return &OnboardSummary{
		OK:                true,
		Applied:           true,
		Mode:              "apply",
		Sealed:            sealedMode,
		KeyID:             keyID,
		Verified:          verified,
		TenantID:          resolvedTenantID,
		Slug:              slug,
		AppName:           appName,
		TenantDisplayName: tenantDisplayName,
		TenantDomain:      tenantDomain,
		AuthorizedByEmail: authorizedEmail,
		ClientID:          app.AppID,
		SPObjectID:        sp.ObjectID,
		SecretMasked:      MaskSecret(cred.SecretText),
		SecretExpiresAt:   expiresAtISO,
		FreezeRoleMode:    freezeMode,
		RolesPerSub:       roles,
		Subscriptions:     assigned,
		OutputPath:        outPath,
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

func effectiveKeyID(custom string, plain bool) string {
	if plain {
		return ""
	}
	if s := strings.TrimSpace(custom); s != "" {
		return s
	}
	return DefaultSealKeyID
}

func writeSecureJSON(path string, payload any) error {
	raw, err := json.MarshalIndent(payload, "", "  ")
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
