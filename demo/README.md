# mcplens demo

`demo.gif` (top of the repo README) renders two live `mcplens scan --probes`
runs made on Nov 9, 2026. The full record is here:

| File | What it is |
|---|---|
| `scan-ticketdesk.txt` / `.json` | Scan of TicketDesk, a real read-only MCP server (copy in this folder; built for the Argus Chat demo). **Grade A, 100/100, zero findings** — probes observed only what the tool descriptions declare. |
| `scan-vulnerable.txt` / `.json` | Scan of `fixtures/vulnerable_server.py`, the repo's deliberately hostile fixture. **Grade F, 0/100, 5 findings (4 critical, 1 high)** — static rules catch the poisoned `add` description (MCPL001/003) and the unconstrained shell parameter (MCPL005); runtime probes catch what static reading cannot: the "read-only" `get_system_info` returning canary credential contents (MCPL101) and modifying the filesystem (MCPL103). |
| `transcript.txt` | Every command run for the demo, with full output and exit codes. |
| `run_demo.py` | Re-runs both scans and rewrites the reports. |
| `ticketdesk_server.py` | The TicketDesk server, copied from the Argus Chat demo so this demo is self-contained. |

The GIF is a text rendering of the captured terminal output in
`transcript.txt` — the numbers in it are the scanners' own, from these runs.
