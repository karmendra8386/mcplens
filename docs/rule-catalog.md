# mcplens rule catalog

All rules carry a stable ID, a severity, and a mapping to the
[OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/).

## Static rules (tool definitions)

| ID | Severity | Title | OWASP |
|---|---|---|---|
| MCPL001 | critical | Instruction injection in tool description ("ignore previous instructions", "do not tell the user", `<IMPORTANT>`, "before calling this tool, first…") | MCP05 Tool Poisoning & Prompt Injection |
| MCPL002 | high | Hidden or bidirectional Unicode (zero-width chars, bidi overrides, Unicode tag chars) in name/description | MCP05 |
| MCPL003 | critical | Description references sensitive files (`~/.ssh`, `id_rsa`, `/etc/passwd`, `.aws/credentials`, `.env`, `.gnupg`, …) | MCP05 |
| MCPL004 | medium | Look-alike tool names that differ only by case/separators (shadowing) | MCP05 |
| MCPL005 | high | Unconstrained shell/command parameter (free-form string named `command`/`cmd`/`shell`/`script`/`code`/… with no enum or pattern) | MCP04 Command Injection & Execution |
| MCPL006 | medium | Parameter declares no type constraint | MCP09 Protocol & Transport Vulnerabilities |
| MCPL007 | medium | inputSchema sets `additionalProperties: true` | MCP06 Privilege Escalation & Excessive Permissions |
| MCPL008 | medium | Read-only-sounding tool (`get_`, `list_`, `read_`, …) whose description describes write/exec behavior | MCP06 |
| MCPL009 | low | Excessive tool count (> 50 tools) | MCP02 Context Over-Sharing |
| MCPL010 | high | Duplicate tool names within one server | MCP05 |
| MCPL011 | medium | Description claims broad data access (environment variables, "all files", home directory, …) | MCP02 |
| MCPL012 | low | Unusually long description (> 2000 characters) | MCP05 |
| MCPL013 | medium | Server target uses plaintext `http://` | MCP09 |
| MCPL014 | medium | Tool accepts a secret (`password`, `api_key`, `secret`, …) as a plain string parameter | MCP01 Token Mismanagement & Secret Exposure |
| MCPL015 | low | Tool has no description | MCP08 Audit Logging & Accountability |

## Behavioral probe rules (runtime)

These fire only under `mcplens scan --probes`, from observed behavior in the
sandbox — never from claims.

| ID | Severity | Title | OWASP |
|---|---|---|---|
| MCPL101 | critical | Tool response contained a canary token planted in a fake credential file (undeclared sensitive-file read) | MCP02 |
| MCPL102 | high | Tool created/modified/deleted sandbox files without any write behavior in its description | MCP06 |
| MCPL103 | critical | Tool presents as read-only (name prefix or explicit claim) but modified the filesystem | MCP06 |
| MCPL104 | high | Tool fetched the probe URL it was handed while its description declares no network use | MCP02 |
| MCPL105 | low | Tool errored when invoked with benign, schema-derived arguments | MCP08 |

## Grading

Score starts at 100; subtract 40 per critical, 20 per high, 8 per medium,
3 per low, 1 per info (floor 0).
A ≥ 90 · B ≥ 75 · C ≥ 60 · D ≥ 40 · F < 40.
