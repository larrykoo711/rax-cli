package azure

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultSealPublicKeyParsesAsRSA2048(t *testing.T) {
	pub, err := ParseRSAPublicKeyPEM(DefaultSealPublicKeyPEM)
	if err != nil {
		t.Fatalf("ParseRSAPublicKeyPEM failed: %v", err)
	}
	if pub.Size() != 256 {
		t.Fatalf("expected 2048-bit (256-byte) RSA key, got %d bytes", pub.Size())
	}
}

func TestSealAndUnsealRoundTripAndAADTamperDetection(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	spkiBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal SPKI: %v", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spkiBytes}))

	bundle := OnboardBundle{
		Schema:          "rax-azure-tenant-bundle/v1",
		TenantID:        "11111111-2222-3333-4444-555555555555",
		Slug:            "hailiang01",
		AppName:         "rax-managed-sp-hailiang01",
		ClientID:        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		SPObjectID:      "sp-obj-1",
		ClientSecret:    "super-secret-value-9999",
		SecretExpiresAt: "2027-11-26T00:00:00Z",
		FreezeRoleMode:  "custom",
	}

	now := time.Date(2026, 11, 26, 6, 30, 0, 0, time.UTC)
	sealed, err := SealBundle(bundle, true, now, "test-kid", pubPEM)
	if err != nil {
		t.Fatalf("SealBundle failed: %v", err)
	}
	if sealed.Schema != SealedBundleSchema || sealed.Alg != SealedBundleAlg || sealed.KeyID != "test-kid" {
		t.Fatalf("unexpected envelope header: %+v", sealed)
	}
	if sealed.Metadata.SecretMasked != "***9999" || !sealed.Metadata.Verified {
		t.Fatalf("unexpected metadata: %+v", sealed.Metadata)
	}

	// Valid round-trip decryption.
	plain, err := UnsealBundle(sealed, priv)
	if err != nil {
		t.Fatalf("UnsealBundle failed: %v", err)
	}
	if plain.ClientSecret != "super-secret-value-9999" || plain.TenantID != bundle.TenantID || plain.ClientID != bundle.ClientID {
		t.Fatalf("decrypted payload mismatch: %+v", plain)
	}

	// Tampering with AAD-authenticated metadata must fail decryption.
	tampered := *sealed
	tampered.Metadata.TenantID = "99999999-2222-3333-4444-555555555555"
	if _, err := UnsealBundle(&tampered, priv); err == nil {
		t.Fatalf("expected AAD tamper to fail decryption, but succeeded")
	}
}

func TestDefaultBundleOutputPathUsesDownloadsRaxCLI(t *testing.T) {
	now := time.Date(2026, 11, 26, 6, 30, 45, 0, time.UTC)
	p := DefaultBundleOutputPath("HaiLiang 01!", now, false)
	if !strings.Contains(p, filepath.Join("Downloads", "rax-cli")) {
		t.Fatalf("expected path under Downloads/rax-cli, got %s", p)
	}
	if !strings.HasSuffix(p, "rax-hailiang-01-20261126-063045.rax.enc.json") {
		t.Fatalf("unexpected filename: %s", p)
	}
}
