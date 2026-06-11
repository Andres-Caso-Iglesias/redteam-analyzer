# Deployment Guide

Step-by-step instructions for deploying redteam-analyzer on Kali Linux.

---

## Prerequisites

- Kali Linux (tested on latest rolling release)
- Python 3.10 or higher
- Internet connection (for installing dependencies and tool updates)
- Root or sudo access (for installing system-level tools)

---

## 1. Install System Dependencies

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-venv python3-pip git
```

---

## 2. Clone the Repository

```bash
cd ~/Desktop
git clone https://github.com/your-org/redteam-analyzer.git
cd redteam-analyzer
```

---

## 3. Create a Virtual Environment

Kali Linux blocks direct `pip install` due to PEP 668. Always use a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

To activate the environment in future sessions:

```bash
cd ~/Desktop/redteam-analyzer
source .venv/bin/activate
```

---

## 4. Install the Project

```bash
pip install -e .
```

This installs the project in editable mode. Any changes to the source code take effect immediately without reinstallation.

### Install with Development Dependencies

```bash
pip install -e ".[dev]"
```

This additionally installs pytest, pytest-asyncio, pytest-cov, mypy, and ruff.

---

## 5. Install External Tools

redteam-analyzer delegates to external tools for scanning. Install the ones you need:

### nmap (required for port scanning)

```bash
sudo apt install -y nmap
nmap --version
```

### nuclei (required for vulnerability template scanning)

Download the pre-built binary (no Go installation required):

```bash
cd /tmp
NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
curl -LO "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
unzip "nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
sudo mv nuclei /usr/local/bin/
sudo chmod +x /usr/local/bin/nuclei
nuclei -version
```

### whatweb (required for web fingerprinting)

```bash
sudo apt install -y whatweb
whatweb --version
```

### masscan (optional, alternative to nmap)

```bash
sudo apt install -y masscan
masscan --version
```

---

## 6. Verify Installation

```bash
# Activate environment
source .venv/bin/activate

# Check CLI is available
redteam-analyzer --help

# List available plugins
redteam-analyzer plugin list

# Run tests
pytest -v

# Dry run (no network calls)
redteam-analyzer scan example.com --dry-run
```

---

## 7. Configuration

### Using a Config File

```bash
cp config.example.yaml config.yaml
# Edit config.yaml with your settings
redteam-analyzer config validate config.yaml
redteam-analyzer scan example.com -c config.yaml
```

### Using Environment Variables

All config options can be overridden via environment variables:

```bash
export RTA_DRY_RUN=true
export RTA_AUTH_TOKEN=your-token-here
export RTA_MODULES=recon,scan
redteam-analyzer scan example.com
```

---

## 8. Running in tmux

For long-running scans, use tmux to prevent session disconnection:

```bash
# Create a new tmux session
tmux new-session -s rta

# Activate environment and run scan
cd ~/Desktop/redteam-analyzer
source .venv/bin/activate
redteam-analyzer scan 10.129.95.191 -vvv

# Detach: Ctrl+B, then D
# Reattach: tmux attach -t rta
```

---

## Updating

```bash
cd ~/Desktop/redteam-analyzer
source .venv/bin/activate
git pull
pip install -e .
```

---

## Uninstalling

```bash
cd ~/Desktop/redteam-analyzer
deactivate  # Exit the virtual environment
rm -rf .venv
rm -rf src/redteam_analyzer.egg-info
```

---

## Troubleshooting

See [troubleshooting.md](troubleshooting.md) for known issues and their solutions.
