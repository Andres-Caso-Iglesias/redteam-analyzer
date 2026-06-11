# redteam-analyzer

CLI tool for red team security analysis -- reconnaissance, port scanning, vulnerability detection, and reporting.

> **LEGAL DISCLAIMER:** This tool is authorized for use ONLY on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal. Users are solely responsible for compliance with all applicable laws. The authors assume no liability for misuse.

---

## Motivation

Security professionals need a unified, auditable tool that combines reconnaissance, scanning, and vulnerability detection into a single pipeline with built-in legal guardrails. Most existing tools operate in isolation, lack scope enforcement, and provide no audit trail.

redteam-analyzer addresses these gaps:

- **Unified pipeline** -- recon, scan, vuln, and report in a single command
- **Legal guardrails in code** -- scope validation, rate limiting, and auth gating enforced at the engine level
- **Audit logging** -- every action recorded with timestamp, target, module, and outcome
- **Plugin architecture** -- extensible modules that run independently and fail gracefully
- **Progress visibility** -- real-time nmap progress with configurable verbosity

---

## Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.10+ |
| CLI Framework | Typer |
| Terminal Output | Rich |
| Data Models | Pydantic v2 |
| HTTP Client | httpx |
| Config Format | YAML |
| Templating | Jinja2 |
| Testing | pytest, pytest-asyncio |
| Type Checking | mypy |
| Linting | ruff |

### External Tools

| Tool | Purpose | Required |
|------|---------|:--------:|
| nmap | Port scanning | Yes |
| nuclei | Vulnerability template scanning | Optional |
| whatweb | Web fingerprinting | Optional |
| masscan | Fast port scanning (alternative to nmap) | Optional |

---

## Installation

```bash
git clone https://github.com/your-org/redteam-analyzer.git
cd redteam-analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

See [docs/en/deployment.md](docs/en/deployment.md) for detailed deployment instructions including external tool installation.

---

## Quick Start

```bash
# Dry run (no network calls -- safe to test configuration)
redteam-analyzer scan example.com --dry-run

# Full scan against authorized target
redteam-analyzer scan 192.168.1.100 --auth-token YOUR_TOKEN

# Passive recon only
redteam-analyzer recon example.com --passive-only

# Scan with real-time progress
redteam-analyzer scan 10.129.95.191 -vv

# Generate report from existing results
redteam-analyzer report scan-results.json -f html -f markdown -o report
```

---

## Commands

| Command | Description |
|---------|-------------|
| `redteam-analyzer scan <target>` | Full security scan pipeline |
| `redteam-analyzer recon <target>` | Reconnaissance only |
| `redteam-analyzer report <file>` | Generate report from JSON results |
| `redteam-analyzer config validate <file>` | Validate configuration file |
| `redteam-analyzer plugin list` | List available plugins |

### Verbosity Levels

| Flag | Output |
|------|--------|
| (none) | Spinner with phase status |
| `-v` | Detailed findings after scan |
| `-vv` | Real-time nmap progress percentage |
| `-vvv` | Raw nmap output line by line |

---

## Modules

| Module | Description | Requires Auth |
|--------|-------------|:---:|
| `recon` | Passive and active reconnaissance | No |
| `scan` | Port scanning via nmap or masscan | No |
| `vuln` | CVE matching and Nuclei template scanning | Yes |
| `report` | JSON, HTML, and Markdown report generation | No |

---

## Configuration

```bash
cp config.example.yaml config.yaml
redteam-analyzer config validate config.yaml
redteam-analyzer scan example.com -c config.yaml
```

All options support environment variable overrides with the `RTA_` prefix. See [docs/en/usage.md](docs/en/usage.md) for the full reference.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/en/architecture.md) | Technical architecture and design decisions |
| [Deployment Guide](docs/en/deployment.md) | Step-by-step installation on Kali Linux |
| [Usage Guide](docs/en/usage.md) | Complete command reference and workflow |
| [Troubleshooting](docs/en/troubleshooting.md) | Known issues and their solutions |

### Spanish Documentation

| Documento | Descripcion |
|-----------|-------------|
| [Arquitectura](docs/es/architecture.md) | Arquitectura tecnica y decisiones de diseno |
| [Guia de Despliegue](docs/es/deployment.md) | Instalacion paso a paso en Kali Linux |
| [Guia de Uso](docs/es/usage.md) | Referencia completa de comandos y flujo de trabajo |
| [Solucion de Problemas](docs/es/troubleshooting.md) | Problemas conocidos y sus soluciones |

---

## Project Structure

```
redteam-analyzer/
├── src/redteam_analyzer/
│   ├── cli/              # Typer app + Rich output
│   ├── core/             # Engine, models, scope validation
│   ├── modules/          # Scan plugins (recon, scan, vuln, report)
│   └── utils/            # Rate limiter, audit log, external tools
├── tests/                # 135 tests (unit, integration, E2E)
├── docs/                 # Documentation (en/, es/)
├── config.example.yaml   # Example configuration
└── pyproject.toml        # Project configuration
```

---

## Development

```bash
pip install -e ".[dev]"
pytest -v                          # Run all tests
pytest --cov=redteam_analyzer      # Coverage report
mypy src/                          # Type checking
ruff check src/                    # Linting
```

---

## License

MIT
