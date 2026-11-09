"""Reproduce the mcplens demo scans.

Runs `mcplens scan --probes` against two real MCP servers:

1. TicketDesk (demo/ticketdesk_server.py — a copy of the support-ticket
   MCP server built for the Argus Chat demo; an honest, read-only server)
2. The deliberately vulnerable fixture in fixtures/vulnerable_server.py

Writes scan-ticketdesk.txt/.json and scan-vulnerable.txt/.json next to
this script. Requires mcplens installed (pip install -e . from the repo
root) — the scans invoke the `mcplens` CLI and `sys.executable` as the
server interpreter, so run this with the same Python env.

    python demo/run_demo.py
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


def scan(name, server_path):
    cmd = [sys.executable, "-m", "mcplens.cli", "scan", "--probes",
           "--cmd", f"{sys.executable} {server_path}"]
    text = subprocess.run(cmd, capture_output=True, text=True)
    (HERE / f"scan-{name}.txt").write_text(text.stdout)
    print(text.stdout)
    js = subprocess.run(cmd + ["--format", "json"], capture_output=True, text=True)
    (HERE / f"scan-{name}.json").write_text(js.stdout)


if __name__ == "__main__":
    scan("ticketdesk", HERE / "ticketdesk_server.py")
    scan("vulnerable", ROOT / "fixtures" / "vulnerable_server.py")
