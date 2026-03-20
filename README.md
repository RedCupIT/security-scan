# security-scan

Centralized security scanning for every repository in the organization, powered by **Semgrep** (SAST) and **Trivy** (vulnerability + secret + misconfiguration scanning).

Scans trigger automatically when a **PR is opened/updated** or a **new repo is created** in the org. Results appear as:
- **Status checks** directly on the PR (pass/fail per scanner)
- **A comment** in the PR with a findings summary table
- **Code scanning alerts** in each repo's Security tab (via SARIF)

---

## How it works

```
GitHub Org event
  │  (pull_request opened/sync'd, or repository created)
  ▼
Org Webhook  ──►  Cloudflare Worker (relay)
                       │
                       │  repository_dispatch
                       ▼
              security-scan repo (this repo)
                       │
           ┌───────────┴───────────┐
           ▼                       ▼
      Semgrep SAST            Trivy scan
           │                       │
           └───────────┬───────────┘
                       ▼
              Post to target PR:
                ✅/❌  Commit status checks
                💬  PR comment with summary table
                📊  SARIF → Security tab
```

---

## Setup

### Step 1 — Deploy the webhook relay

The relay is a Cloudflare Worker that validates and forwards org webhook events.

```bash
cd webhook-relay
npm install -g wrangler
wrangler login

# Set secrets
wrangler secret put GITHUB_WEBHOOK_SECRET   # any random string — you'll use this in Step 2
wrangler secret put GITHUB_TOKEN            # PAT with repo + security_events + read:org

# Set your org name in wrangler.toml, then deploy
wrangler deploy
```

The deploy output will give you a URL like `https://security-scan-relay.YOUR_ACCOUNT.workers.dev`.

> **No Cloudflare account?** You can use any small serverless platform (AWS Lambda + API Gateway, Railway, Render, etc.) — the `worker.js` logic is standard JavaScript. Or use [smee.io](https://smee.io) for testing.

---

### Step 2 — Configure the org webhook

1. Go to **GitHub → Your Org → Settings → Webhooks → Add webhook**
2. Set:
   - **Payload URL**: your Cloudflare Worker URL from Step 1
   - **Content type**: `application/json`
   - **Secret**: the same random string you used for `GITHUB_WEBHOOK_SECRET`
   - **Events**: select **individual events** → check:
     - `Pull requests`
     - `Repositories`
3. Save.

---

### Step 3 — Set secrets and variables on this repo

Go to **this repo → Settings → Secrets and variables → Actions**:

| Secret | Description |
|--------|-------------|
| `ORG_SCAN_TOKEN` | GitHub PAT with `repo`, `security_events`, and `read:org` scopes |
| `SEMGREP_APP_TOKEN` | (Optional) Semgrep Cloud token for the managed dashboard |

| Variable | Description |
|----------|-------------|
| `ORG_NAME` | Your GitHub organization name (e.g. `my-org`) |

---

### Step 4 — Protect the status checks (optional but recommended)

In each repo (or at the org level via a ruleset):

1. **Settings → Branches → Branch protection rules → main**
2. Enable **Require status checks to pass before merging**
3. Add `security/semgrep` and `security/trivy` as required checks

This blocks merging PRs that have critical findings.

---

## What the PR comment looks like

```
🔴 Security Scan Results — Action required

| Scanner              | Critical | High | Medium | Total | Status       |
|----------------------|:--------:|:----:|:------:|:-----:|--------------|
| 🔴 Semgrep (SAST)    |    2     |  4   |   7    |  13   | Issues found |
| 🟢 Trivy (vulns+sec) |    0     |  0   |   0    |   0   | Clean ✅     |

> View full findings in the Security tab.

Scan run: #42 · Commit: `a1b2c3d`
```

The comment is **updated in place** on subsequent pushes — no comment spam.

---

## Configuration

### Semgrep rulesets

The workflow currently runs these Semgrep rulesets (edit `org-security-scan.yml` to change):

- `p/owasp-top-ten` — OWASP Top 10
- `p/secrets` — Hardcoded credentials
- `p/javascript`, `p/python`, `p/golang` — Language-specific rules
- `p/docker`, `p/terraform` — Infrastructure rules

### Trivy severity threshold

Edit the `severity` input in the Trivy job to adjust which findings are reported:
```yaml
severity: CRITICAL,HIGH,MEDIUM   # default
```

### Skip paths / custom secret patterns

See [`configs/trivy/trivy.yaml`](configs/trivy/trivy.yaml) and [`configs/trivy/trivy-secret.yaml`](configs/trivy/trivy-secret.yaml).

---

## Manual scan

Trigger from **Actions → Org-Wide Security Scan → Run workflow**.
Enter `owner/repo` and optionally a SHA or PR number.

---

## File structure

```
.github/workflows/
  org-security-scan.yml       # Main workflow (event-driven)
  reusable-semgrep.yml        # Optional: call from individual repos
  reusable-trivy.yml          # Optional: call from individual repos
configs/
  semgrep/semgrep.yml         # Semgrep rule configuration
  trivy/
    trivy.yaml                # Trivy scan configuration
    trivy-secret.yaml         # Custom secret detection rules
webhook-relay/
  worker.js                   # Cloudflare Worker relay
  wrangler.toml               # Cloudflare deployment config
```
