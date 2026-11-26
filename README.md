# rax-cli

Standalone, zero-dependency CLI for [Rax](https://rax.72ray.com) cloud tenant onboarding and verification.

- **Zero runtime dependencies**: single static Go binary — no Python, no Node.js, no `az` CLI required.
- **Zero plaintext secret on disk**: onboarding bundles are sealed in memory using **RSA-OAEP-256 + AES-256-GCM** with Rax's platform public key (`keyId: rax-onboard-v1`) and saved to `~/Downloads/rax-cli/rax-<slug>-<timestamp>.rax.enc.json` (`0600`). Only Rax Console can decrypt `clientSecret`.
- **AI Agent-Ready**: `--agent` NDJSON event streaming, `rax agent-info` machine-readable schema, `rax doctor --json` preflight, and standardized exit codes (`0/1/2/3/4`).
- **Platforms**: macOS (`arm64` / `amd64`) via Homebrew, Linux (`amd64` / `arm64`) via install script or GitHub Releases.

## Install & Upgrade

### macOS (Homebrew)

```bash
brew install larrykoo711/tap/rax
# Upgrade later:
brew upgrade larrykoo711/tap/rax
```

### Linux

```bash
curl -fsSL https://raw.githubusercontent.com/larrykoo711/rax-cli/main/install.sh | sh
# Upgrade later:
rax upgrade
```

## Quick Start

### 1. Onboard an Azure Tenant (Native Device Code → Encrypted Bundle)

```bash
# Dry-run plan (zero Azure writes)
rax azure onboard --slug hailiang01

# Live onboarding: Device Code login -> auto-discover enabled subscriptions
# -> create single-tenant SP + 4 read roles + custom least-privilege freeze role
# -> self-verify in memory -> save encrypted bundle to ~/Downloads/rax-cli/
rax azure onboard --slug hailiang01 --secret-days 365 --apply
```

Upload the generated `~/Downloads/rax-cli/rax-hailiang01-*.rax.enc.json` file in **Rax Console → Azure → 租户与订阅 → 接入租户 (Step 2)**.

### 2. AI Agent Readiness (Claude Code / Codex / OpenCode)

```bash
# Machine-readable CLI schema, exit codes, and security boundary
rax agent-info

# Environment & Entra/Graph/ARM HTTPS connectivity preflight
rax doctor --json

# Line-flushed NDJSON event stream (step / device_code / done / error)
rax azure onboard --slug hailiang01 --secret-days 365 --agent --apply
```

### 3. Validate a Sealed Bundle Envelope

```bash
rax azure verify --bundle ~/Downloads/rax-cli/rax-hailiang01-*.rax.enc.json --json
```
