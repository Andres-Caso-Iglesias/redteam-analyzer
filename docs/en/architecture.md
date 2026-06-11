# Architecture Overview

Technical architecture of redteam-analyzer.

---

## Design Principles

1. **Plugin-based architecture** — Each scanning capability is an independent plugin. The core engine knows nothing about specific tools.
2. **Legal guardrails in code** — Scope validation, rate limiting, and auth gating are enforced at the engine level, not bolted on as afterthoughts.
3. **Defense in depth** — Plugin failures do not crash the scan. Each plugin is isolated and its errors are captured.
4. **Subprocess isolation** — External tools (nmap, nuclei, whatweb) run as subprocesses. No Python library bindings that could introduce version conflicts.

---

## High-Level Architecture

```
CLI (Typer + Rich)
    |
    v
Engine
    |
    +-- ScopeValidator    (rejects out-of-scope targets)
    +-- RateLimiter       (per-domain token bucket)
    +-- AuditLogger       (every action logged)
    +-- PluginManager     (discovers and loads plugins)
    |
    v
Plugins (sequential execution)
    |
    +-- ReconPlugin   (crt.sh, DNS, VirusTotal, Shodan, WhatWeb, dirbust)
    +-- ScanPlugin    (nmap, masscan)
    +-- VulnPlugin    (CVE matching, Nuclei templates)
    +-- ReportPlugin  (JSON, HTML, Markdown generation)
```

---

## Core Components

### Engine (`src/redteam_analyzer/core/engine.py`)

The Engine is the single point of control. It orchestrates the entire scan pipeline:

1. Validates target scope before any network call
2. Filters modules based on auth availability
3. Executes plugins sequentially via `PluginManager`
4. Merges results from all plugins into a single `ScanResult`
5. Logs every action to the audit trail
6. Handles plugin failures gracefully (one plugin crashing does not stop others)

### PluginManager (`src/redteam_analyzer/core/plugin_manager.py`)

Responsible for discovering, loading, and managing plugins:

- Discovers plugins by scanning `src/redteam_analyzer/modules/` for `BasePlugin` subclasses
- Searches both package-level attributes and submodules (handles empty `__init__.py`)
- Caches loaded plugin instances
- Validates plugin dependencies before execution

### ScopeValidator (`src/redteam_analyzer/core/scope.py`)

Enforces target scope restrictions:

- Validates IPs against CIDR ranges
- Validates domains against allowed patterns (including wildcards)
- Validates URLs against allowed hosts
- Raises `ScopeError` for out-of-scope targets — this exception is caught by the Engine and logged

### RateLimiter (`src/redteam_analyzer/utils/rate_limiter.py`)

Prevents accidental denial-of-service:

- Token bucket algorithm with configurable capacity and refill rate
- Per-domain buckets (each domain gets its own rate limit)
- Global bucket (overall rate limit across all domains)
- Async-compatible with `asyncio.sleep` for non-blocking waits

### AuditLogger (`src/redteam_analyzer/utils/audit_log.py`)

Maintains a complete audit trail:

- Every action (scan start, plugin start/complete, errors) is logged
- Entries include timestamp, target, module, action, success/failure, and error details
- Persisted to `audit_log.json` at scan completion
- Queryable by target and module for post-scan analysis

---

## Plugin Architecture

### BasePlugin (`src/redteam_analyzer/modules/base.py`)

Abstract base class that all plugins must implement:

```python
class BasePlugin(ABC):
    name: str
    description: str

    @abstractmethod
    async def run(self, target: Target, config: ScanConfig) -> ScanResult:

    @abstractmethod
    def validate_dependencies(self) -> List[ToolInfo]:
```

### Plugin Lifecycle

1. **Discovery** — PluginManager scans module packages for `BasePlugin` subclasses
2. **Loading** — Plugin instance is created and cached
3. **Dependency check** — `validate_dependencies()` verifies required tools are installed
4. **Execution** — `run()` is called with the target and accumulated config
5. **Result merge** — Plugin's `ScanResult` is merged into the accumulated result

### Plugin Isolation

Each plugin runs in a try/except block within the Engine. If a plugin raises an exception:

- The error is logged to the audit trail
- The error message is added to `ScanResult.errors`
- The Engine continues with the next plugin

This means a failing Nuclei scan does not prevent report generation from partial results.

---

## Data Models (`src/redteam_analyzer/core/models.py`)

All data models use Pydantic v2 for validation and serialization:

| Model | Purpose |
|-------|---------|
| `Target` | Represents a scan target (IP, hostname, URL) |
| `Finding` | A single vulnerability or information finding |
| `ScanResult` | Accumulated results from plugin execution |
| `ScanConfig` | Full scan configuration |
| `ScopeConfig` | Target scope restrictions |
| `ScanMetadata` | Plugin execution metadata (duration, timestamp) |
| `ToolInfo` | External tool availability information |

---

## External Tool Integration

All external tools run as subprocesses via `run_tool()` in `src/redteam_analyzer/utils/external_tools.py`:

- **stdout** is captured and parsed (XML for nmap, JSONL for nuclei)
- **stderr** is optionally streamed to a progress callback (handles both `\n` and `\r` line endings)
- **Timeouts** are enforced per-tool with configurable limits
- **Errors** are wrapped in `ToolNotFoundError` or `ToolTimeoutError`

### Why subprocesses, not Python libraries?

- Version isolation: nmap Python bindings conflict with system nmap
- Security: subprocesses are naturally sandboxed
- Reliability: system-installed tools are maintained by the OS
- Flexibility: can swap nmap for masscan without code changes

---

## Test Structure

```
tests/
├── test_core/          # Unit tests for engine, models, scope
├── test_modules/       # Unit tests for each plugin
├── test_cli/           # CLI integration tests
├── test_utils/         # Unit tests for rate limiter, audit log
└── e2e/                # End-to-end integration tests
```

- **135 tests** all passing
- Uses `pytest-asyncio` with `asyncio_mode=auto`
- E2E tests run the full pipeline with mocked external tools
- Unit tests mock at the subprocess boundary

---

## Technology Stack

| Component | Technology |
|-----------|------------|
| CLI framework | Typer |
| Terminal output | Rich |
| Data models | Pydantic v2 |
| HTTP client | httpx |
| Config format | YAML (PyYAML) |
| Templating | Jinja2 |
| Testing | pytest, pytest-asyncio |
| Type checking | mypy |
| Linting | ruff |
| Package management | setuptools |
