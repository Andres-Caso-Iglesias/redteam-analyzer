# Usage Guide

Comprehensive reference for using redteam-analyzer.

---

## Commands Overview

| Command | Description |
|---------|-------------|
| `redteam-analyzer scan <target>` | Run full security scan (recon + scan + vuln + report) |
| `redteam-analyzer recon <target>` | Run reconnaissance only |
| `redteam-analyzer report <file>` | Generate report from existing JSON results |
| `redteam-analyzer config validate <file>` | Validate a configuration file |
| `redteam-analyzer plugin list` | List available scan plugins |

---

## Scan Command

Runs the full scanning pipeline: reconnaissance, port scanning, vulnerability detection, and reporting.

### Basic Usage

```bash
redteam-analyzer scan <TARGET> [OPTIONS]
```

### Options

| Flag | Short | Description |
|------|-------|-------------|
| `--module` | `-m` | Modules to run (repeatable). Default: all |
| `--output` | `-o` | Output file path |
| `--format` | `-f` | Output format: json, html, markdown (repeatable) |
| `--config` | `-c` | Config file path |
| `--dry-run` | `-d` | Dry run mode (no network calls) |
| `--auth-token` | `-t` | Auth token for intrusive modules |
| `--passive-only` | `-p` | Passive recon only |
| `--verbose` | `-v` | Verbosity level (repeatable) |
| `--new-terminal` | `-T` | Open scan in a new terminal window |

### Verbosity Levels

The `-v` flag can be stacked to increase output detail:

| Level | Flag | Output |
|-------|------|--------|
| 0 | (none) | Spinner with phase status |
| 1 | `-v` | Detailed findings after scan |
| 2 | `-vv` | Real-time nmap progress percentage |
| 3 | `-vvv` | Raw nmap output line by line |

### Examples

```bash
# Dry run (safe, no network calls)
redteam-analyzer scan example.com --dry-run

# Full scan with auth token
redteam-analyzer scan 192.168.1.100 --auth-token YOUR_TOKEN

# Scan with specific modules only
redteam-analyzer scan example.com -m recon -m scan

# Scan with real-time progress
redteam-analyzer scan 10.129.95.191 -vv

# Scan with verbose findings
redteam-analyzer scan 10.129.95.191 -v

# Full verbose (progress + raw output)
redteam-analyzer scan 10.129.95.191 -vvv

# Output to multiple formats
redteam-analyzer scan example.com -f json -f html -o results
```

---

## Recon Command

Runs reconnaissance against a target. Useful for information gathering before a full scan.

### Basic Usage

```bash
redteam-analyzer recon <TARGET> [OPTIONS]
```

### Options

| Flag | Short | Description |
|------|-------|-------------|
| `--passive-only` | `-p` | Passive recon only (no direct requests to target) |
| `--output` | `-o` | Output file path |
| `--verbose` | `-v` | Verbosity level (repeatable) |
| `--new-terminal` | `-T` | Open recon in a new terminal window |

### Examples

```bash
# Passive recon only (crt.sh, DNS, VirusTotal, Shodan)
redteam-analyzer recon example.com --passive-only

# Full recon (passive + active: fingerprinting, directory bust)
redteam-analyzer recon example.com -v
```

### Recon Modules

| Module | Type | Description |
|--------|------|-------------|
| crt.sh | Passive | Certificate transparency logs |
| DNS | Passive | DNS record enumeration |
| VirusTotal | Passive | Domain reputation (requires API key) |
| Shodan | Passive | Internet-wide scan data (requires API key) |
| WhatWeb | Active | Web technology fingerprinting |
| Directory bust | Active | Hidden path discovery |

---

## Report Command

Generates reports from previously saved scan results.

### Basic Usage

```bash
redteam-analyzer report <FILE> [OPTIONS]
```

### Options

| Flag | Short | Description |
|------|-------|-------------|
| `--format` | `-f` | Output format: json, html, markdown (repeatable) |
| `--template` | `-t` | HTML template: default or executive |
| `--output` | `-o` | Output file path |

### Examples

```bash
# Generate HTML report
redteam-analyzer report scan-results.json -f html -o report.html

# Generate executive summary
redteam-analyzer report scan-results.json -f html -t executive -o exec-report.html

# Generate all formats
redteam-analyzer report scan-results.json -f json -f html -f markdown -o report
```

---

## Configuration

### Config File

Copy the example configuration and customize:

```bash
cp config.example.yaml config.yaml
```

```yaml
# config.yaml
scope:
  allowed_targets:
    - "192.168.1.0/24"
    - "example.com"
  rate_limit: 20

modules:
  - recon
  - scan
  - vuln
  - report

scan_backend: nmap
passive_only: false
```

Validate before use:

```bash
redteam-analyzer config validate config.yaml
```

### Environment Variables

All config options can be overridden via environment variables with the `RTA_` prefix:

| Variable | Config Key | Example |
|----------|------------|---------|
| `RTA_DRY_RUN` | `dry_run` | `true` |
| `RTA_AUTH_TOKEN` | `auth_token` | `your-token` |
| `RTA_MODULES` | `modules` | `recon,scan` |
| `RTA_OUTPUT_FORMAT` | `output_format` | `json,html` |
| `RTA_OUTPUT_PATH` | `output_path` | `results.json` |
| `RTA_PASSIVE_ONLY` | `passive_only` | `true` |
| `RTA_SCAN_BACKEND` | `scan_backend` | `nmap` |
| `RTA_REPORT_TEMPLATE` | `report_template` | `executive` |
| `RTA_SCOPE_RATE_LIMIT` | `scope.rate_limit` | `20` |

---

## Modules

| Module | Description | Requires Auth |
|--------|-------------|:---:|
| `recon` | Passive and active reconnaissance | No |
| `scan` | Port scanning via nmap or masscan | No |
| `vuln` | CVE matching and Nuclei template scanning | Yes (for nuclei) |
| `report` | Generate JSON, HTML, and Markdown reports | No |

### Module Execution Order

Modules execute in the order defined in the config (default: recon, scan, vuln, report). Each module receives the accumulated results from previous modules.

### Auth-Gated Modules

The `vuln` module uses Nuclei, which can perform intrusive checks. It requires an `--auth-token` to run. Without it, only passive vulnerability checks (CVE matching) are performed.

```bash
# Without auth: only CVE matching
redteam-analyzer scan example.com -m vuln

# With auth: CVE matching + Nuclei templates
redteam-analyzer scan example.com -m vuln --auth-token YOUR_TOKEN
```

---

## Legal Guardrails

redteam-analyzer enforces several legal guardrails in code:

1. **Scope validation** — All targets are validated against the configured scope before any network call. Out-of-scope targets are rejected with a `ScopeError`.

2. **Rate limiting** — Per-domain and global rate limits prevent accidental denial-of-service.

3. **Auth gating** — Intrusive modules (Nuclei templates) require explicit authentication.

4. **Audit logging** — Every action is logged to `audit_log.json` with timestamp, target, module, action, and success/failure status.

5. **Dry run mode** — `--dry-run` executes the full pipeline without making any network calls. Use this to verify configuration before live scanning.

---

## Typical Workflow

```bash
# 1. Set up environment
cd ~/Desktop/redteam-analyzer
source .venv/bin/activate

# 2. Validate configuration
redteam-analyzer config validate config.yaml

# 3. Dry run to verify
redteam-analyzer scan 10.129.95.191 --dry-run

# 4. Run recon first
redteam-analyzer recon 10.129.95.191 -v

# 5. Full scan with progress
redteam-analyzer scan 10.129.95.191 -vv

# 6. Generate report
redteam-analyzer report scan-results.json -f html -f markdown -o report
```
