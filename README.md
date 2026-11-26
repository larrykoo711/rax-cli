# rax-cli

Zero-dependency standalone CLI for **Rax** (Cloud LLM Channel Control Tower) — written in pure Go (no Python, no Node.js, no `az` CLI required).

## Install

### macOS (Homebrew)
```bash
brew install larrykoo711/tap/rax
```

### Linux / macOS (curl)
```bash
curl -fsSL https://raw.githubusercontent.com/larrykoo711/rax-cli/main/install.sh | sh
```

## Commands

### 1. Onboard an Azure Tenant via Native Entra Device Code
Single browser sign-in automatically discovers all enabled subscriptions under the tenant, creates a single-tenant Service Principal with a time-bounded secret, provisions the least-privilege `Rax Foundry Freeze Operator` custom role + 4 read-only roles, and exports a `chmod 600` onboarding bundle for Rax Console:

```bash
rax azure onboard \
  --slug prod \
  --secret-days 365 \
  --output ./rax-onboard-bundle.json \
  --apply
```

Omit `--apply` for a zero-write dry-run preview.

### 2. Verify a Service Principal Bundle
```bash
rax azure verify --bundle ./rax-onboard-bundle.json
```

### 3. Version & Self-Upgrade
```bash
rax version
rax upgrade
```

## Security Posture
- Tokens from Device Code sign-in live strictly in process memory and are never persisted to `~/.azure` or disk.
- Generated bundle JSON is written with `chmod 0600`; raw secrets are never echoed to stdout/stderr.
- Custom freeze role explicitly denies `accounts/delete`, `listKeys`, and `regenerateKey`.

## License
MIT
