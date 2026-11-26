# rax-cli

Zero-dependency, **agent-ready** CLI for **Rax** (Cloud LLM Channel Control Tower) — written in pure Go (no Python, no Node.js, no `az` CLI required).

## Install

### macOS (Homebrew)
```bash
brew install larrykoo711/tap/rax
```

### Linux / macOS (curl)
```bash
curl -fsSL https://raw.githubusercontent.com/larrykoo711/rax-cli/main/install.sh | sh
```

## AI Agent Readiness (Claude Code / Codex / OpenCode / Any Harness)

`rax` is built first-class for AI coding agents acting on behalf of an operator:
- **`rax agent-info`** — emits machine-readable command schemas, exit codes (`0/1/2/3/4`), and zero-secret-leakage rules.
- **`--agent` / `RAX_AGENT=1`** — switches `rax azure onboard` to line-flushed **NDJSON** on stdout (`step`, `device_code`, `done`, `error`), so agents immediately detect `verificationUri` + `userCode` and relay them to the user.
- **`rax doctor --json`** — 1-second preflight verifying HTTPS reachability to Entra, Graph, and ARM endpoints.
- **Zero secret leakage**: raw `clientSecret` is written strictly to the `chmod 600` bundle file and is never emitted to stdout/stderr.

```bash
rax azure onboard --slug prod --secret-days 365 --output ./rax-onboard-bundle.json --agent --apply
rax azure verify --bundle ./rax-onboard-bundle.json --json
```

## Human Terminal Usage

```bash
# Dry-run preview (zero Azure writes)
rax azure onboard --slug prod

# Live Device Code onboarding (auto-discovers all enabled subscriptions)
rax azure onboard --slug prod --secret-days 365 --output ./rax-onboard-bundle.json --apply

# Verify Service Principal tokens & visible subscriptions
rax azure verify --bundle ./rax-onboard-bundle.json

# Preflight & self-upgrade
rax doctor
rax version
rax upgrade
```

## License
MIT
