# MCPSafe
![PyPI](https://img.shields.io/pypi/v/mcpsafe)
![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.11+-blue)
![Tests](https://img.shields.io/badge/tests-91-green)

> MCP has 97 million installs. Zero dedicated security testing tools exist for it. Until now.

## What is MCPSafe?

MCPSafe is an open-source CLI that connects to any MCP server and runs 91 security and performance tests across 8 modules, then produces a JSON and HTML report with color-coded severity findings. Works with any MCP-compatible client including Claude Code, Cursor, and Windsurf.

## Quick Start

```bash
pip install mcpsafe
```

Scan a stdio server:

```bash
mcpsafe scan "python my_server.py"
```

Scan an HTTP server:

```bash
mcpsafe scan "http://localhost:8000" --transport http
```

Run only security modules, skip load tests:

```bash
mcpsafe scan "python my_server.py" --modules injection,poison,auth --no-load
```

## What It Tests

| Module | Tests | What it finds |
|--------|-------|---------------|
| discovery | 8 | Server identity, tool enumeration, duplicate names, oversized descriptions |
| injection | 16 | Prompt injection, shell injection (`$HOME`, `$(whoami)`), path traversal (`../../../etc/passwd`), null bytes, Unicode smuggling (RTL override), Base64 payloads, large payload DoS |
| fuzzer | 41 | Boundary values (min/max int32, empty string, null), type confusion (dict as string, string as int), prototype pollution, deeply nested objects, null byte injection |
| poison | 5 | Rug-pull attacks (tool description mutation after connect), hidden Unicode in descriptions, cross-tool invocation instructions, Base64-encoded payloads in schemas, tool count instability |
| load | 4 | 10 simultaneous calls with UUID cross-leakage detection, p50/p95/p99 latency (50 calls), 100-call stress test, rapid reconnect stability |
| schema | 5 | JSON Schema structural validity, required field enforcement, additionalProperties strictness, return type consistency, overly permissive schemas |
| auth | 7 | Unauthenticated access (raw HTTP bypass), malformed token acceptance, resource URI path traversal, credential exposure in error messages, CORS wildcard, root process check, env variable probe |
| latency | 5 | Per-tool baseline latency, discovery latency, resource read latency, cold-start detection, degradation under load vs baseline |

## Real Vulnerabilities MCPSafe Catches

1. **CVE-2025-6514** — OS command injection in mcp-remote (437,000 downloads).
   Malicious servers could achieve remote code execution on the client machine.
   MCPSafe catches this via: T02 injection module + T07-001 unauthenticated access.

2. **Tool description rug-pull attacks** (documented by Invariant Labs, 2025).
   A tool appears safe on Day 1 but silently redefines its description to exfiltrate data by Day 7.
   MCPSafe catches this via: T04-001 mutation detection (snapshots descriptions, waits 3s, compares).

3. **WhatsApp MCP data exfiltration via tool poisoning** (Invariant Labs, 2025).
   Malicious tool description containing hidden instructions exfiltrated entire chat history.
   MCPSafe catches this via: T04-002 hidden instruction pattern matching.

4. **CVE-2025-68145** — Path validation bypass in Anthropic's own mcp-server-git.
   Three chained vulnerabilities enabling arbitrary file access and code execution.
   MCPSafe catches this via: T07-003 resource URI path traversal tests.

5. **Cross-request data leakage in StreamableHTTPServerTransport** (CVSS 7.1, MCP TypeScript SDK).
   One client may receive data intended for another client under concurrent load.
   MCPSafe catches this via: T05-001 UUID-per-call cross-leakage detection.

## Example Output

```
╭─────────────────────────────────────────────╮
│ MCPSafe v0.1.0                              │
│ MCP Server Security & Stress Tester         │
│ github.com/your-handle/mcpsafe              │
╰─────────────────────────────────────────────╯

Target:     python my_server.py
Transport:  stdio
Server:     my-data-server v1.0.0
Tools:      4   Resources: 2   Prompts: 0

Running 8 modules (91 tests)...

  ✓ Discovery        8/8    0 findings
  ✓ Latency          5/5    0 findings
  ✓ Schema           5/5    1 finding  [LOW]
  ⚠ Injection       16/16   2 findings [MEDIUM]
  ✗ Poison           5/5    1 finding  [CRITICAL]
  ✓ Auth             7/7    0 findings
  ✓ Load             4/4    0 findings

┌──────────┬───────┬──────────────────────────────────────┐
│ Severity │ Count │ Distribution                         │
├──────────┼───────┼──────────────────────────────────────┤
│ CRITICAL │   1   │ ███                                  │
│ HIGH     │   0   │                                      │
│ MEDIUM   │   2   │ ██████                               │
│ LOW      │   1   │ ███                                  │
│ PASS     │  87   │ ██████████████████████████████████   │
└──────────┴───────┴──────────────────────────────────────┘

Reports saved:
  JSON → ./mcpsafe-reports/mcpsafe-a1b2c3d4-20260413.json
  HTML → ./mcpsafe-reports/mcpsafe-a1b2c3d4-20260413.html

Exiting with code 1 — CRITICAL findings require attention.
```

## CI/CD Integration

MCPSafe exits with code 1 if CRITICAL or HIGH findings are detected, making it suitable as a pipeline gate:

```yaml
- name: Security scan MCP server
  run: |
    pip install mcpsafe
    mcpsafe scan "python src/server.py" --no-load --output json
  # Pipeline fails automatically on CRITICAL or HIGH findings
```

## Options Reference

| Option | Default | Description |
|--------|---------|-------------|
| `--transport` | `stdio` | Transport protocol: `stdio`, `http`, `sse` |
| `--modules` | `all` | Comma-separated list of modules to run |
| `--output` | `both` | Report format: `json`, `html`, `both` |
| `--out-dir` | `./mcpsafe-reports` | Directory to save reports |
| `--timeout` | `10` | Seconds per MCP call before timeout |
| `--concurrency` | `10` | Max concurrent calls during load tests |
| `--no-load` | `false` | Skip large payload and stress tests |
| `--verbose` | `false` | Print each finding as it is discovered |

## Why MCPSafe?

MCP reached 97 million installs in under 18 months, faster than nearly any developer protocol in history. In that time, documented vulnerabilities accumulated: command injection, tool poisoning, path traversal, credential exposure, cross-request data leakage. No standardized testing tool existed. Every team building on MCP was deploying without a way to verify their server was safe.

Most security tools check documentation. MCPSafe connects to your actual running server and sends adversarial inputs — the same payloads real attackers use. The injection module sends 16 payloads including Unicode smuggling and large-payload DoS probes. The poison module waits 3 seconds and checks whether your tool descriptions mutated. The load module embeds unique UUIDs in concurrent requests and checks whether responses leak data across boundaries.

MCPSafe works against any MCP server regardless of language, framework, or vendor. It speaks the MCP protocol directly. Whether your server is built with FastMCP, the TypeScript SDK, a custom implementation, or a third-party package with 437,000 downloads — MCPSafe tests it the same way.

## Contributing

PRs welcome. Please open an issue first for major changes.

Run tests:

```bash
pytest
```

Lint and format checks:

```bash
ruff check .
black --check .
```

## License

MIT — see LICENSE file.
