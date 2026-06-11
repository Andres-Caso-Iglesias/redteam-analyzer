# redteam-analyzer

CLI tool for red team security analysis — reconnaissance, port scanning, vulnerability detection, and reporting.

> **LEGAL DISCLAIMER:** This tool is authorized for use ONLY on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal. Users are solely responsible for compliance with all applicable laws. The authors assume no liability for misuse.

## Installation

```bash
# From source
git clone https://github.com/your-org/redteam-analyzer.git
cd redteam-analyzer
pip install -e ".[dev]"

# Or install directly
pip install .
```

### Requirements

- Python 3.10+
- External tools (install separately based on modules you need):
  - **nmap** — Port scanning (`scan` module)
  - **masscan** — Fast port scanning (alternative to nmap)
  - **nuclei** — Vulnerability templates (`vuln` module)
  - **whatweb** — Web fingerprinting (`recon` module)

## Quick Start

```bash
# Dry run (no network calls — safe to test)
redteam-analyzer scan example.com --dry-run

# Full scan against authorized target
redteam-analyzer scan 192.168.1.100 --auth-token YOUR_TOKEN

# Passive recon only
redteam-analyzer recon example.com --passive-only

# Scan with specific modules
redteam-analyzer scan example.com -m recon -m scan

# Generate report from existing results
redteam-analyzer report scan-results.json -f html -f markdown
```

## Commands

| Command | Description |
|---------|-------------|
| `redteam-analyzer scan <target>` | Run full security scan |
| `redteam-analyzer recon <target>` | Run reconnaissance only |
| `redteam-analyzer report <file>` | Generate report from JSON results |
| `redteam-analyzer config validate <file>` | Validate a config file |
| `redteam-analyzer plugin list` | List available scan plugins |

### scan

```
redteam-analyzer scan <TARGET> [OPTIONS]

Arguments:
  TARGET  Target IP, hostname, URL, or CIDR [required]

Options:
  -m, --module TEXT        Modules to run (repeatable). Default: all
  -o, --output TEXT        Output file path
  -f, --format TEXT        Output format: json, html, markdown (repeatable)
  -c, --config TEXT        Config file path
  -d, --dry-run            Dry run mode (no network calls)
  -t, --auth-token TEXT    Auth token for intrusive modules
  -p, --passive-only       Passive recon only
  -v, --verbose            Verbose output with full finding details
  --help                   Show this message and exit
```

### recon

```
redteam-analyzer recon <TARGET> [OPTIONS]

Options:
  -p, --passive-only    Passive recon only
  -o, --output TEXT     Output file path
  -v, --verbose         Verbose output
```

### report

```
redteam-analyzer report <FILE> [OPTIONS]

Arguments:
  FILE  Scan results file (JSON) [required]

Options:
  -f, --format TEXT     Output format: json, html, markdown (repeatable)
  -t, --template TEXT   HTML template: default or executive
  -o, --output TEXT     Output file path
```

## Configuration

Copy `config.example.yaml` to `config.yaml` and customize:

```bash
redteam-analyzer config validate config.yaml
redteam-analyzer scan example.com -c config.yaml
```

### Environment Variables

All config options can be overridden via environment variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `RTA_DRY_RUN` | Dry run mode | `true` |
| `RTA_AUTH_TOKEN` | Auth token | `your-token` |
| `RTA_MODULES` | Modules (comma-sep) | `recon,scan` |
| `RTA_OUTPUT_FORMAT` | Formats (comma-sep) | `json,html` |
| `RTA_OUTPUT_PATH` | Output path | `results.json` |
| `RTA_PASSIVE_ONLY` | Passive only | `true` |
| `RTA_SCAN_BACKEND` | Scan backend | `nmap` |
| `RTA_REPORT_TEMPLATE` | HTML template | `executive` |
| `RTA_SCOPE_RATE_LIMIT` | Rate limit/sec | `20` |

## Modules

| Module | Description | Requires Auth |
|--------|-------------|:---:|
| `recon` | Passive & active reconnaissance (crt.sh, VirusTotal, Shodan, DNS, directory bust, fingerprinting) | No |
| `scan` | Port scanning via nmap or masscan | No |
| `vuln` | CVE matching + Nuclei template scanning | Yes (for nuclei) |
| `report` | Generate JSON, HTML, and Markdown reports | No |

## Project Structure

```
redteam-analyzer/
├── src/redteam_analyzer/
│   ├── cli/              # Typer app + Rich output
│   │   ├── main.py       # CLI entry point
│   │   ├── output.py     # Rich formatting helpers
│   │   └── config.py     # Config loading
│   ├── core/             # Engine + models
│   │   ├── models.py     # Pydantic models
│   │   ├── engine.py     # Scan orchestration
│   │   ├── plugin_manager.py
│   │   └── scope.py      # Scope validation
│   ├── modules/          # Scan plugins
│   │   ├── base.py       # BasePlugin ABC
│   │   ├── recon/        # Reconnaissance
│   │   ├── scan/         # Port scanning
│   │   ├── vuln/         # Vulnerability detection
│   │   └── report/       # Report generation
│   └── utils/            # Utilities
│       ├── rate_limiter.py
│       ├── audit_log.py
│       └── external_tools.py
├── tests/
│   ├── test_core/        # Core tests
│   ├── test_modules/     # Module tests
│   ├── test_cli/         # CLI tests
│   ├── test_utils/       # Utility tests
│   └── e2e/              # Integration tests
├── config.example.yaml   # Example configuration
└── pyproject.toml        # Project config
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest -v

# Run only E2E tests
pytest -v -m e2e

# Run with coverage
pytest --cov=redteam_analyzer --cov-report=term-missing

# Type checking
mypy src/

# Linting
ruff check src/
```

## License

MIT
