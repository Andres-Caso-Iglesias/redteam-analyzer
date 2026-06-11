# Troubleshooting Guide

This document catalogs all known issues encountered during development and deployment, along with their root causes and solutions.

---

## 1. PluginManager Fails to Discover Plugins

### Symptoms

```
Plugin 'scan' not found, skipping
Plugin 'recon' not found, skipping
```

All plugins are reported as missing despite being present in the source tree.

### Root Cause

The `PluginManager` only searched for a `plugin` attribute directly inside each module's `__init__.py`. In this project, each module (e.g., `scan`, `recon`, `vuln`, `report`) is a Python package with an empty `__init__.py` and the actual plugin class living in a submodule (`scan/plugin.py`, `recon/plugin.py`, etc.).

### Solution

Added a `_find_base_plugin_in_module()` method that searches the module for any subclass of `BasePlugin`. If the direct attribute lookup fails, the manager now iterates through the module's submodules looking for the plugin class.

**File:** `src/redteam_analyzer/core/plugin_manager.py`

```python
def _find_base_plugin_in_module(self, module):
    """Search for BasePlugin subclass in module and its submodules."""
    # Direct attribute check first
    for attr_name in dir(module):
        attr = getattr(module, attr_name)
        if isinstance(attr, type) and issubclass(attr, BasePlugin) and attr is not BasePlugin:
            return attr()

    # Submodule search (e.g., scan.plugin)
    for attr_name in dir(module):
        attr = getattr(module, attr_name)
        if isinstance(attr, types.ModuleType):
            for sub_attr_name in dir(attr):
                sub_attr = getattr(attr, sub_attr_name)
                if isinstance(sub_attr, type) and issubclass(sub_attr, BasePlugin) and sub_attr is not BasePlugin:
                    return sub_attr()
    return None
```

### Lesson Learned

When designing a plugin system, always account for the difference between a package (directory with `__init__.py`) and a module (single `.py` file). Empty `__init__.py` files are common in Python packages — do not assume the plugin class lives at the package level.

---

## 2. TokenBucket Rate Limiter Bypass

### Symptoms

Rate limiting does not work as expected. Tokens are consumed but the bucket never properly waits for refill when empty.

### Root Cause

The `_wait_for_token` method used `<= 0` as the condition to wait for refill:

```python
while self.tokens <= 0:
    await asyncio.sleep(wait_time)
```

When `tokens` hit exactly `0`, the loop would execute one more iteration, wait, and then proceed with `tokens` still at `0` (or a fractional value from partial refill). This allowed requests to pass through without a full token being available.

### Solution

Changed the condition to `< 1`, ensuring the caller waits until a full token is available:

```python
while self.tokens < 1:
    await asyncio.sleep(wait_time)
```

**File:** `src/redteam_analyzer/utils/rate_limiter.py`

### Lesson Learned

Rate limiters must ensure atomic token consumption. A token bucket with capacity `N` and refill rate `R` tokens/sec should only grant access when a full integer token is available. Floating-point comparisons near zero are treacherous — always use strict inequality (`< 1`) instead of less-than-or-equal (`<= 0`).

---

## 3. Pydantic v2 Silently Drops Undefined Attributes

### Symptoms

The nmap progress callback (`on_progress`) was never invoked. The CLI showed only a static "Scanning..." spinner with no progress updates, despite the callback being correctly defined and assigned.

### Root Cause

Pydantic v2 `BaseModel` does not allow setting arbitrary attributes on model instances. The following code fails silently:

```python
scan_config._on_progress = callback  # Silently discarded
```

When the scan plugin later retrieves the callback:

```python
on_progress = getattr(config, "_on_progress", None)  # Always None
```

It gets `None` because Pydantic silently rejected the attribute assignment.

### Solution

Added `on_progress` as a proper field on `ScanConfig` with `exclude=True` (so it is not serialized) and `arbitrary_types_allowed=True` (so it can hold a callable):

```python
from pydantic import BaseModel, ConfigDict, Field

class ScanConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    # ... other fields ...
    on_progress: Optional[Any] = Field(default=None, exclude=True)
```

**Files:**
- `src/redteam_analyzer/core/models.py` — field definition
- `src/redteam_analyzer/cli/main.py` — assignment changed from `_on_progress` to `on_progress`
- `src/redteam_analyzer/modules/scan/plugin.py` — retrieval changed to `getattr(config, "on_progress", None)`

### Lesson Learned

Pydantic v2 is strict about model schemas. Unlike Pydantic v1 (which had `allow_population_by_field_name` and was more lenient), v2 rejects any attribute not declared in the model. When you need to pass non-serializable objects (callbacks, connection pools, etc.) through a Pydantic model, you must declare them as fields with `exclude=True` and set `arbitrary_types_allowed=True` in the model config.

---

## 4. Nmap Progress Not Displayed (Carriage Return Issue)

### Symptoms

Even after fixing the Pydantic callback issue, the CLI still showed no progress updates from nmap. The spinner remained static throughout the scan.

### Root Cause

Nmap writes progress updates to stderr using carriage returns (`\r`) instead of newlines (`\n`). The original `_read_stderr_progress` function used `readline()`, which blocks until it encounters a `\n` character:

```python
async def _read_stderr_progress(stderr_stream, on_progress):
    while True:
        line = await stderr_stream.readline()  # Blocks waiting for \n
        if not line:
            break
        text = line.decode(errors="replace").rstrip()
        if text:
            on_progress(text)
```

Since nmap never sends `\n` during progress updates (only `\r`), `readline()` blocks indefinitely, and the callback is never invoked.

### Solution

Rewrote `_read_stderr_progress` to read raw bytes in chunks and split on both `\r` and `\n`:

```python
async def _read_stderr_progress(stderr_stream, on_progress):
    buffer = ""
    while True:
        chunk = await stderr_stream.read(1024)
        if not chunk:
            break
        text = chunk.decode(errors="replace")
        for char in text:
            if char in ("\n", "\r"):
                if buffer.strip():
                    on_progress(buffer.strip())
                buffer = ""
            else:
                buffer += char
    if buffer.strip():
        on_progress(buffer.strip())
```

**File:** `src/redteam_analyzer/utils/external_tools.py`

### Lesson Learned

Different tools use different line-ending conventions for progress output. Nmap uses `\r` to overwrite the same line (like a progress bar). When building a subprocess output reader that must handle progress from arbitrary tools, always split on both `\r` and `\n`, and use chunk-based reading instead of `readline()`.

Nmap progress output format:
```
SYN Stealth Scan Timing: About 15.35% done; ETC: 14:46 (0:02:51 remaining)
```

---

## 5. Indentation Error in Scan Plugin

### Symptoms

```
IndentationError: unexpected indent
```

Tests fail to collect with an indentation error in `plugin.py`.

### Root Cause

During a previous edit, an extra indentation level was introduced on the `on_progress` assignment line:

```python
        # Get progress callback from config if available
            on_progress = getattr(config, "on_progress", None)  # Extra indent
```

### Solution

Removed the extra indentation to align with the surrounding code block:

```python
        # Get progress callback from config if available
        on_progress = getattr(config, "on_progress", None)
```

**File:** `src/redteam_analyzer/modules/scan/plugin.py`

### Lesson Learned

Always run tests after edits. Indentation errors in Python are syntax errors and will crash the entire module. Use an editor with visible whitespace to catch these issues early.

---

## 6. pip install Blocked by PEP 668 (Kali Linux)

### Symptoms

```
error: externally-managed-environment
```

`pip install` fails on Kali Linux because the system Python is externally managed.

### Root Cause

Kali Linux (and many modern Linux distributions) mark the system Python as externally managed per PEP 668. This prevents `pip install` from modifying system packages to avoid breaking OS tools.

### Solution

Use a virtual environment:

```bash
cd ~/Desktop/redteam-analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Or use `--break-system-packages` (not recommended for production):

```bash
pip install -e . --break-system-packages
```

### Lesson Learned

Always use virtual environments for Python projects. It isolates dependencies, avoids conflicts with system packages, and is the standard practice in modern Python development.

---

## 7. `--new-terminal` Flag Fails Inside tmux

### Symptoms

The `-T` flag to open a new terminal window does not work. The command either hangs or falls back to running in the current terminal.

### Root Cause

The `--new-terminal` flag attempts to detect and launch a graphical terminal emulator (gnome-terminal, xfce4-terminal, etc.). When running inside tmux, these GUI terminals may not be accessible, or the environment variables (`$DISPLAY`, `$TERM`) may not point to a graphical session.

### Current Status

Deferred. The flag is implemented but falls back gracefully to running in the current terminal. A future improvement would be to detect tmux and use `tmux new-window` instead.

### Workaround

Run the scan directly without `-T`. Use tmux panes or windows manually to parallelize work.

---

## Summary of All Fixes

| Issue | File(s) Affected | Fix |
|-------|-------------------|-----|
| PluginManager submodule discovery | `core/plugin_manager.py` | Added submodule search for `BasePlugin` subclasses |
| TokenBucket rate limiter bypass | `utils/rate_limiter.py` | Changed `<= 0` to `< 1` |
| Pydantic v2 drops on_progress | `core/models.py`, `cli/main.py`, `modules/scan/plugin.py` | Added `on_progress` as proper Pydantic field |
| Nmap progress not displayed | `utils/external_tools.py` | Rewrote stderr reader to handle `\r` line endings |
| Indentation error | `modules/scan/plugin.py` | Fixed extra indentation |
| PEP 668 on Kali | N/A (environment) | Use `python3 -m venv .venv` |
| `--new-terminal` in tmux | `cli/terminal.py` | Deferred; falls back gracefully |
