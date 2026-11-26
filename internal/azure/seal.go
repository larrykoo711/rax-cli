package azure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	// SealedBundleSchema identifies an asymmetric hybrid-encrypted Rax onboarding bundle.
	SealedBundleSchema = "rax-azure-sealed-bundle/v1"
	// SealedBundleAlg describes the envelope cipher suite (RSA-OAEP-SHA256 key wrap + AES-256-GCM payload).
	SealedBundleAlg = "RSA-OAEP-256+A256GCM"
	// DefaultSealKeyID identifies the embedded Rax platform public key used to seal bundles.
	DefaultSealKeyID = "rax-onboard-v1"
)

// DefaultSealPublicKeyPEM is the public RSA-2048 encryption key of the Rax Console platform.
// Only the Rax Console Cloudflare Worker holds the matching private key secret.
const DefaultSealPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbvuiVIQbt23d08nuRqs
GjhlIdlZMThDBIO+JGGMuxWsJvDVOAqgtDbxlBcsOnjR8MOCGs4JUbikn+Z2IlCW
Tj27tEZ5YwQh3oTWbxu6fRH4XfEm2qFNOs1oZ01Tvj7G9CWkdGsR0oGt3HfAleYC
FRje98qBSCLhOro8ywFPDbgcoIa1E+5Vgi9Kka7o6fYfhHdQK/HHGNl54F1j2NK/
gWKCdqGJ4brnzsoXzIuED7m9MDx/Bau4+ZVnRVOxzVVLrDF2RESUtwBnwFJfc2Cg
Gdv8oZHyTJJ8pw4/TfZ1ktk58bRxq7+dT+mXbmr8KsUKAV6963FjQWE4RaKBlbd6
XwIDAQAB
-----END PUBLIC KEY-----`

// SealedBundleMetadata carries non-sensitive tenant metadata authenticated via AES-GCM AAD.
type SealedBundleMetadata struct {
	TenantID          string                      `json:"tenantId"`
	Slug              string                      `json:"slug"`
	AppName           string                      `json:"appName"`
	TenantDisplayName string                      `json:"tenantDisplayName,omitempty"`
	TenantDomain      string                      `json:"tenantDomain,omitempty"`
	AuthorizedByEmail string                      `json:"authorizedByEmail,omitempty"`
	ClientID          string                      `json:"clientId"`
	SPObjectID        string                      `json:"spObjectId"`
	SecretMasked      string                      `json:"secretMasked"`
	SecretExpiresAt   string                      `json:"secretExpiresAt"`
	FreezeRoleMode    string                      `json:"freezeRoleMode"`
	Verified          bool                        `json:"verified"`
	Subscriptions     []OnboardBundleSubscription `json:"subscriptions"`
}

// SealedCiphertext holds the RSA-OAEP wrapped DEK, 12-byte GCM IV, and ciphertext+tag.
type SealedCiphertext struct {
	EK string `json:"ek"`
	IV string `json:"iv"`
	CT string `json:"ct"`
}

// SealedOnboardBundle is the encrypted file written to ~/Downloads/rax-cli/*.rax.enc.json.
// Plaintext clientSecret never touches disk and can only be decrypted by Rax Console.
type SealedOnboardBundle struct {
	Schema    string               `json:"schema"`
	Alg       string               `json:"alg"`
	KeyID     string               `json:"keyId"`
	CreatedAt string               `json:"createdAt"`
	Metadata  SealedBundleMetadata `json:"metadata"`
	Sealed    SealedCiphertext     `json:"sealed"`
}

// SealedSecretPayload is the JSON plaintext encrypted inside Sealed.CT.
type SealedSecretPayload struct {
	TenantID        string `json:"tenantId"`
	ClientID        string `json:"clientId"`
	ClientSecret    string `json:"clientSecret"`
	SecretExpiresAt string `json:"secretExpiresAt"`
}

var unsafeSlugRe = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// SanitizeSlug normalizes a tenant slug into a safe filename token.
func SanitizeSlug(slug string) string {
	s := strings.TrimSpace(slug)
	s = unsafeSlugRe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-._")
	if s == "" {
		return "azure"
	}
	return strings.ToLower(s)
}

// DefaultBundleDir returns the unified user Downloads output directory: ~/Downloads/rax-cli.
func DefaultBundleDir() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return filepath.Join(".", "rax-cli")
	}
	return filepath.Join(home, "Downloads", "rax-cli")
}

// DefaultBundleFilename returns a collision-free filename for an onboarding bundle.
func DefaultBundleFilename(slug string, now time.Time, plain bool) string {
	ext := ".rax.enc.json"
	if plain {
		ext = ".json"
	}
	ts := now.UTC().Format("20060102-150405")
	return fmt.Sprintf("rax-%s-%s%s", SanitizeSlug(slug), ts, ext)
}

// DefaultBundleOutputPath returns ~/Downloads/rax-cli/rax-<slug>-<YYYYMMDD-HHMMSS>.rax.enc.json.
func DefaultBundleOutputPath(slug string, now time.Time, plain bool) string {
	return filepath.Join(DefaultBundleDir(), DefaultBundleFilename(slug, now, plain))
}

// ResolveOutputPath resolves an explicit --output flag (expanding ~/ and directory paths)
// or falls back to ~/Downloads/rax-cli/rax-<slug>-<timestamp>.rax.enc.json.
func ResolveOutputPath(rawPath, slug string, now time.Time, plain bool) string {
	trimmed := strings.TrimSpace(rawPath)
	if trimmed == "" {
		return DefaultBundleOutputPath(slug, now, plain)
	}
	if strings.HasPrefix(trimmed, "~/") {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			trimmed = filepath.Join(home, trimmed[2:])
		}
	}
	// If the caller passed an existing directory or trailing slash, place the default filename inside it.
	if strings.HasSuffix(trimmed, string(os.PathSeparator)) {
		return filepath.Join(trimmed, DefaultBundleFilename(slug, now, plain))
	}
	if info, err := os.Stat(trimmed); err == nil && info.IsDir() {
		return filepath.Join(trimmed, DefaultBundleFilename(slug, now, plain))
	}
	return trimmed
}

// BuildSealAAD constructs the deterministic AES-GCM AAD binding envelope headers and tenant identity.
func BuildSealAAD(keyID, tenantID, clientID, slug string) []byte {
	return []byte(fmt.Sprintf("%s|%s|%s|%s|%s", SealedBundleSchema, keyID, tenantID, clientID, slug))
}

// ParseRSAPublicKeyPEM parses an SPKI PEM-encoded RSA public key.
func ParseRSAPublicKeyPEM(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemStr)))
	if block == nil {
		return nil, errors.New("invalid RSA public key PEM")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse SPKI public key: %w", err)
	}
	rsaPub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not an RSA key")
	}
	if rsaPub.Size() < 256 {
		return nil, errors.New("RSA public key must be at least 2048 bits")
	}
	return rsaPub, nil
}

// SealBundle encrypts clientSecret using hybrid RSA-OAEP-SHA256 + AES-256-GCM so only
// the Rax Console server holding the matching private key can decrypt it.
func SealBundle(bundle OnboardBundle, verified bool, now time.Time, keyID string, pubKeyPEM string) (*SealedOnboardBundle, error) {
	if strings.TrimSpace(bundle.ClientSecret) == "" {
		return nil, errors.New("cannot seal bundle without clientSecret")
	}
	if strings.TrimSpace(keyID) == "" {
		keyID = DefaultSealKeyID
	}
	if strings.TrimSpace(pubKeyPEM) == "" {
		pubKeyPEM = DefaultSealPublicKeyPEM
	}

	pubKey, err := ParseRSAPublicKeyPEM(pubKeyPEM)
	if err != nil {
		return nil, err
	}

	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("generate DEK: %w", err)
	}
	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()

	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("generate IV: %w", err)
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("init AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("init AES-GCM: %w", err)
	}

	secretPayload := SealedSecretPayload{
		TenantID:        bundle.TenantID,
		ClientID:        bundle.ClientID,
		ClientSecret:    bundle.ClientSecret,
		SecretExpiresAt: bundle.SecretExpiresAt,
	}
	plainBytes, err := json.Marshal(secretPayload)
	if err != nil {
		return nil, fmt.Errorf("marshal secret payload: %w", err)
	}
	defer func() {
		for i := range plainBytes {
			plainBytes[i] = 0
		}
	}()

	aad := BuildSealAAD(keyID, bundle.TenantID, bundle.ClientID, bundle.Slug)
	ciphertext := gcm.Seal(nil, iv, plainBytes, aad)

	wrappedDEK, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, dek, nil)
	if err != nil {
		return nil, fmt.Errorf("wrap DEK with RSA-OAEP: %w", err)
	}

	return &SealedOnboardBundle{
		Schema:    SealedBundleSchema,
		Alg:       SealedBundleAlg,
		KeyID:     keyID,
		CreatedAt: now.UTC().Format(time.RFC3339),
		Metadata: SealedBundleMetadata{
			TenantID:          bundle.TenantID,
			Slug:              bundle.Slug,
			AppName:           bundle.AppName,
			TenantDisplayName: bundle.TenantDisplayName,
			TenantDomain:      bundle.TenantDomain,
			AuthorizedByEmail: bundle.AuthorizedByEmail,
			ClientID:          bundle.ClientID,
			SPObjectID:        bundle.SPObjectID,
			SecretMasked:      MaskSecret(bundle.ClientSecret),
			SecretExpiresAt:   bundle.SecretExpiresAt,
			FreezeRoleMode:    bundle.FreezeRoleMode,
			Verified:          verified,
			Subscriptions:     bundle.Subscriptions,
		},
		Sealed: SealedCiphertext{
			EK: base64.StdEncoding.EncodeToString(wrappedDEK),
			IV: base64.StdEncoding.EncodeToString(iv),
			CT: base64.StdEncoding.EncodeToString(ciphertext),
		},
	}, nil
}

// UnsealBundle decrypts a SealedOnboardBundle using the matching RSA private key (used in tests and server-side verification).
func UnsealBundle(sealed *SealedOnboardBundle, privKey *rsa.PrivateKey) (*SealedSecretPayload, error) {
	if sealed == nil || sealed.Schema != SealedBundleSchema {
		return nil, errors.New("unsupported sealed bundle schema")
	}
	if sealed.Alg != SealedBundleAlg {
		return nil, fmt.Errorf("unsupported sealed bundle algorithm %q", sealed.Alg)
	}
	ek, err := base64.StdEncoding.DecodeString(sealed.Sealed.EK)
	if err != nil {
		return nil, fmt.Errorf("decode ek: %w", err)
	}
	iv, err := base64.StdEncoding.DecodeString(sealed.Sealed.IV)
	if err != nil {
		return nil, fmt.Errorf("decode iv: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(sealed.Sealed.CT)
	if err != nil {
		return nil, fmt.Errorf("decode ct: %w", err)
	}

	dek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, ek, nil)
	if err != nil {
		return nil, fmt.Errorf("unwrap DEK: %w", err)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aad := BuildSealAAD(sealed.KeyID, sealed.Metadata.TenantID, sealed.Metadata.ClientID, sealed.Metadata.Slug)
	plain, err := gcm.Open(nil, iv, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt sealed payload: %w", err)
	}
	var payload SealedSecretPayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal secret payload: %w", err)
	}
	return &payload, nil
}
