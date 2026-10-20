"""
ui.py
=====
Modern CLI presentation formatter and animations for terminal output and recording.
"""

import sys
import time
from typing import Optional

# UTF-8 terminal support
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

WIDTH = 76

# ANSI Colors
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def print_banner():
    banner = f"""
{BOLD}{CYAN}┌{'─' * (WIDTH - 2)}┐
│  eBPF/XDP DDoS Detection & Mitigation Machine Learning Pipeline        │
│  Kernel-Space Line-Rate In-Kernel Inspection • 1-Second Temporal Window│
└{'─' * (WIDTH - 2)}┘{RESET}"""
    print(banner)


def print_section(title: str):
    prefix = f"{BOLD}─── {title} {RESET}"
    fill = max(0, WIDTH - len(title) - 6)
    print(f"\n{prefix}{DIM}{'─' * fill}{RESET}")


def print_step(title: str, status: str = "", note: Optional[str] = None):
    badge = ""
    if status == "DONE" or status == "PASS" or status == "VERIFIED":
        badge = f"{GREEN}[{status}]{RESET}"
    elif status == "RUN" or status == "ACTIVE":
        badge = f"{YELLOW}[{status}]{RESET}"
    elif status == "FAIL":
        badge = f"{RED}[{status}]{RESET}"
    elif status:
        badge = f"[{status}]"

    if badge:
        print(f"  ▸ {title:<52} {badge:>18}")
    else:
        print(f"  ▸ {title}")

    if note:
        print(f"    {DIM}└─ {note}{RESET}")


def print_item(label: str, value: str, note: Optional[str] = None):
    print(f"  • {label:<36} {BOLD}{value:>24}{RESET}")
    if note:
        print(f"    {DIM}└─ {note}{RESET}")


def animated_progress(title: str, duration: float = 0.6, steps: int = 15):
    """Simulates realistic animated progress bar for visual demos / screen recording."""
    if duration <= 0:
        return
    bar_len = 24
    for i in range(steps + 1):
        frac = i / steps
        filled = int(bar_len * frac)
        bar = "█" * filled + "░" * (bar_len - filled)
        pct = int(frac * 100)
        sys.stdout.write(f"\r  ▸ {title:<36} [{bar}] {pct:>3}% ")
        sys.stdout.flush()
        time.sleep(duration / steps)
    sys.stdout.write(f"\r  ▸ {title:<52} {GREEN}[DONE]{RESET}\n")
    sys.stdout.flush()
