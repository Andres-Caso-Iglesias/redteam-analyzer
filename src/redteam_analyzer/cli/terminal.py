"""Terminal detection and launching for redteam-analyzer.

Opens scan/recon commands in a new terminal window.
Supports Linux (Kali), macOS, and Windows.
"""

import os
import platform
import shutil
import subprocess
import sys
from typing import List, Optional


# Linux terminal emulators in order of preference
LINUX_TERMINALS = [
    ("tilix", ["-e"]),
    ("gnome-terminal", ["--"]),
    ("xfce4-terminal", ["-e"]),
    ("konsole", ["-e"]),
    ("xterm", ["-e"]),
    ("lxterminal", ["-e"]),
]


def detect_terminal() -> Optional[str]:
    """Detect an available terminal emulator on the system.

    Returns:
        Terminal command name or None if not found
    """
    system = platform.system()

    if system == "Linux":
        for term_cmd, _ in LINUX_TERMINALS:
            if shutil.which(term_cmd):
                return term_cmd
        return None

    elif system == "Darwin":
        # macOS always has Terminal.app via 'open'
        return "open"

    elif system == "Windows":
        # Windows has wt (Windows Terminal) or cmd
        if shutil.which("wt"):
            return "wt"
        return "cmd"

    return None


def open_new_terminal(args: List[str], terminal: Optional[str] = None) -> bool:
    """Open a new terminal window and execute the given command.

    Args:
        args: Command and arguments to run in the new terminal
        terminal: Specific terminal emulator to use (auto-detect if None)

    Returns:
        True if terminal was opened successfully
    """
    system = platform.system()
    term = terminal or detect_terminal()

    if not term:
        return False

    try:
        if system == "Linux":
            _launch_linux(term, args)
        elif system == "Darwin":
            _launch_macos(args)
        elif system == "Windows":
            _launch_windows(term, args)
        else:
            return False

        return True

    except Exception:
        return False


def _launch_linux(terminal: str, args: List[str]) -> None:
    """Launch command in a Linux terminal emulator."""
    # Find the flag format for the terminal
    for term_cmd, flag_format in LINUX_TERMINALS:
        if term_cmd == terminal:
            # Build command: terminal [flags] "command args..."
            cmd_str = " ".join(args)
            subprocess.Popen(
                [terminal] + flag_format + [cmd_str],
                start_new_session=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return

    # Fallback: try generic -e flag
    cmd_str = " ".join(args)
    subprocess.Popen(
        [terminal, "-e", cmd_str],
        start_new_session=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _launch_macos(args: List[str]) -> None:
    """Launch command in macOS Terminal.app."""
    # Use osascript to open a new Terminal window with the command
    cmd_str = " ".join(args)
    script = f'''
    tell application "Terminal"
        activate
        do script "{cmd_str}"
    end tell
    '''
    subprocess.Popen(
        ["osascript", "-e", script],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _launch_windows(terminal: str, args: List[str]) -> None:
    """Launch command in a Windows terminal."""
    if terminal == "wt":
        # Windows Terminal
        cmd_str = " ".join(args)
        subprocess.Popen(
            ["wt", "cmd", "/c", cmd_str],
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        # cmd /c start
        cmd_str = " ".join(args)
        subprocess.Popen(
            ["cmd", "/c", "start", "cmd", "/k", cmd_str],
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def get_python_exe() -> str:
    """Get the current Python executable path."""
    return sys.executable


def build_rta_command(args: List[str]) -> List[str]:
    """Build the full redteam-analyzer command to run in a new terminal.

    Args:
        args: CLI arguments (e.g. ['scan', '10.129.95.191', '-v'])

    Returns:
        Full command list including Python executable
    """
    python = get_python_exe()
    return [python, "-m", "redteam_analyzer.cli.main"] + args
