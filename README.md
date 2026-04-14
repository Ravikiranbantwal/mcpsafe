# MCPSafe

[![PyPI version](https://img.shields.io/pypi/v/mcpsafe.svg)](https://pypi.org/project/mcpsafe/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: Noncommercial](https://img.shields.io/badge/License-Polyform%20NC-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-6425%20run-green.svg)]()
[![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-blueviolet)](https://sarifweb.azurewebsites.net/)

> MCP has 97 million installs. Most MCP security tools scan static config files or tool descriptions. MCPSafe is the first to connect to a live running server and test actual runtime behavior — including load testing, latency benchmarking, and cross-request data leakage under concurrency.

MCPSafe is the first open-source security and stress-testing framework for MCP (Model Context Protocol) servers. Connect it to any MCP server over stdio or HTTP and get a full audit — prompt injection, path traversal, type confusion, missing auth, load behaviour, and more — in a single command.

## 📖 Interactive Learning Guide

New to MCPSafe or want to understand how the code works? The learning guide covers every module, attack type, and code pattern — with quizzes!

👉 **[Open the MCPSafe Learning Guide](https://ravikiranbantwal.github.io/mcpsafe/mcpsafe-learning-guide.html)**

*(Or open `mcpsafe-learning-guide.html` locally — it's fully self-contained, no internet required.)*

---

## Real-World Results

MCPSafe has audited **14 MCP servers** — including Stripe's, Cloudflare's, and Anthropic's own reference server. All findings below are from the current v0.1.0 build with false-positive fixes applied.

**6,425 tests · 1 CRITICAL · 35 HIGH · 550 MEDIUM · 90.0% pass rate**

| Server | Transport | Tests | CRITICAL | HIGH | MEDIUM | Overall |
|--------|-----------|------:|:--------:|:----:|:------:|:-------:|
| `mcp.stripe.com` *(live, auth)* 💳 | HTTP | 1,363 | **1** | 1 | 170 | 🔴 CRITICAL |
| `@modelcontextprotocol/server-everything` | stdio | 383 | — | **16** | 69 | 🟠 HIGH |
| `@modelcontextprotocol/server-filesystem` | stdio | 558 | — | 1 | 91 | 🟠 HIGH |
| `@modelcontextprotocol/server-github` | stdio | 2,078 | — | 1 | 1 | 🟠 HIGH |
| `mcp-server-sqlite` (uvx) | stdio | 216 | — | **15** | 8 | 🟠 HIGH |
| `mcp_text_processor` (test server) | stdio | 298 | — | 1 | 44 | 🟠 HIGH |
| `docs.mcp.cloudflare.com` *(live)* | HTTP | 74 | — | — | 4 | 🟡 MEDIUM |
| `mcp-server-fetch` (uvx) | stdio | 32 | — | — | 3 | 🟡 MEDIUM |
| `mcp-server-git` (uvx) | stdio | 545 | — | — | 58 | 🟡 MEDIUM |
| `mcp_calculator` (test server) | stdio | 212 | — | — | 20 | 🟡 MEDIUM |
| `mcp_notes` (test server) | stdio | 228 | — | — | 38 | 🟡 MEDIUM |
| `observability.mcp.cloudflare.com` *(live, auth)* | HTTP | 151 | — | — | 2 | 🟡 MEDIUM |
| `simple_server` (test fixture) | stdio | 163 | — | — | 28 | 🟡 MEDIUM |
| `mcp-server-time` (uvx) | stdio | 124 | — | — | 14 | 🟡 MEDIUM |

### Selected Findings

**`mcp.stripe.com` (Stripe Payments, live HTTP, auth)** — 1,363 tests across 31 tools. **T04-001 CRITICAL rug-pull confirmed**: Stripe's production server mutates tool descriptions between consecutive `list_tools()` calls 3 seconds apart — the server itself exhibits the attack pattern MCPSafe is designed to detect. T04-003 HIGH: 8 cross-tool parasitic references in tool descriptions. 170 MEDIUM: injection payloads echoed verbatim by virtually every financial tool including `create_refund`, `cancel_subscription`, `create_invoice`, and `list_payment_intents`.

**`@modelcontextprotocol/server-everything` (Anthropic's reference server)** — 16 HIGH, 0 CRITICAL. Two vulnerability classes: (1) **Stored prompt injection** — 14 HIGH findings from the `args-prompt` prompt template, which embeds raw argument values directly into generated LLM messages; all 14 injection payloads land in the AI's context window. (2) **DoS via integer overflow** — `trigger-long-running-operation` hangs for 35+ seconds on `2147483647` (INT_MAX) and `1e308` (max float), confirmed resource-exhaustion DoS on Anthropic's own reference implementation.

**`mcp-server-sqlite` (uvx)** — 15 HIGH, all from the `mcp-demo` prompt template. The prompt embeds raw argument values into generated messages without sanitisation — all 15 injection payloads (PI-001 through PI-012, PI-015, PI-016) become stored prompt injections. Additionally, the `memo://insights` resource response contains a suspicious pattern flagged as HIGH.

**`@modelcontextprotocol/server-filesystem`** — 91 MEDIUM injection echoes across file-path tools (`read_file`, `write_file`, `list_directory`). The tools pass raw argument strings directly to OS syscalls; malformed paths return OS errors containing the injection payload verbatim. 1 HIGH T07 auth finding.

**`mcp-server-git` (uvx)** — 58 MEDIUM. Git tools pass raw LLM arguments to shell commands without sanitisation. Injection payloads appear verbatim in OS-level error messages (`git status 'Ignore previous instructions…'`), creating a stored injection pathway for any AI model that reads the error output.

**`observability.mcp.cloudflare.com` (Cloudflare Observability, live HTTP, auth)** — 151 tests, 2 MEDIUM. T04-001 detected a description growth (1,001 → 1,603 chars) between calls — consistent with CDN edge truncation rather than a deliberate rug-pull, correctly classified as MEDIUM. Cross-tool workflow references (observability_keys/observability_values) detected and classified LOW.

---

## Quick Start

```bash
pip install mcpsafe
```

```bash
# Scan a local stdio server
mcpsafe scan "uvx mcp-server-git"

# Scan an HTTP server (Streamable HTTP auto-detected on /mcp endpoints)
mcpsafe scan "https://docs.mcp.cloudflare.com/mcp" --transport http

# Scan an HTTP server that requires authentication
mcpsafe scan "https://observability.mcp.cloudflare.com/mcp" --transport http \
  --header "Authorization=Bearer cfat_your_token_here"

# Pass multiple HTTP headers
mcpsafe scan "https://api.example.com/mcp" --transport http \
  --header "Authorization=Bearer token" \
  --header "X-Org-ID=my-org"

# Output JSON + HTML + SARIF (all formats)
mcpsafe scan "npx -y @modelcontextprotocol/server-filesystem /tmp" --output all

# Pass subprocess environment variables (stdio servers only)
mcpsafe scan "uvx mcp-server-github" --env GITHUB_TOKEN=ghp_xxx

# Generate a config file
mcpsafe init

# Compare two scans to track regressions
mcpsafe compare report-v1.json report-v2.json
```

---

## What It Tests

MCPSafe runs **117 test types** across **8 modules** covering discovery, security, performance, and schema validation.

| Module | Category | Tests | What It Checks |
|--------|----------|------:|----------------|
| **T01** Discovery | DISCOVERY | 6 | Server enumeration, tool listing, resource/prompt exposure, metadata consistency |
| **T02** Injection | SECURITY | 12 | Prompt injection (PI-001–PI-005), jailbreak attempts, system prompt leakage |
| **T03** Fuzzer | SECURITY | 60 | Type confusion, boundary values, oversized payloads, deep nesting, NaN/Infinity |
| **T04** Tool Poison | SECURITY | 8 | Tool description mutation (rug-pull attacks), baseline drift, hidden instructions |
| **T05** Load | PERFORMANCE | 8 | Concurrent load, burst testing, sustained throughput, latency degradation |
| **T06** Schema | SCHEMA | 6 | JSON Schema validation, required field enforcement, description quality |
| **T07** Auth | SECURITY | 13 | Missing auth, Bearer bypass, API key abuse, protocol version abuse, replay attacks |
| **T08** Latency | PERFORMANCE | 4 | Baseline latency, P95/P99 percentiles, timeout behaviour |

### Real Vulnerabilities MCPSafe Catches

**Prompt injection via tool arguments** — The injection module (T02) sends 12 payloads per tool including classic overrides ("Ignore previous instructions…"), role-confusion, system prompt extraction, and Base64-encoded instructions. Confirmed CRITICAL on `mcp-server-git`, `server-filesystem`, and 8 other servers tested.

**Tool description rug-pull attacks** (documented by Invariant Labs, 2025) — A tool appears safe on connect but its description silently mutates to include data-exfiltration instructions. T04 snapshots all tool descriptions on connect and re-checks after a delay to detect mutation.

**SQL/shell injection through string parameters** — T02 sends SQL metacharacters, UNION attacks, and shell metacharacters to every string-typed tool parameter. Confirmed CRITICAL on `mcp-server-sqlite` `write_query`.

**Path traversal in resource URIs** — T07-003 tests `../` sequences and absolute paths in resource URIs. Confirmed on `server-filesystem`.

**Cross-request data leakage under concurrency** — T05-001 embeds unique UUIDs in concurrent requests and checks whether responses contain data intended for a different caller — the same class of bug found in the MCP TypeScript SDK (CVSS 7.1).

**Missing authentication on HTTP endpoints** — T07-001 attempts raw HTTP access to MCP endpoints without credentials and detects servers that respond successfully when they should require auth.

### T03 Fuzzer — 60 Fuzz Cases

- **String attacks**: null bytes, Unicode overlong sequences, ANSI escapes, format strings (`%s %n`), 1MB payloads
- **Integer boundary**: `MAX_INT32+1`, `MIN_INT32-1`, beyond int64 (`9_223_372_036_854_775_808`), zero, negatives
- **Type confusion**: strings where integers expected (`"NaN"`, `"Infinity"`, `"-1"`), objects in array slots
- **Array attacks**: 10,000-element array, mixed-type array (1,000 elements), 100-level deep nested array
- **Number edge cases**: `"NaN"`, `"Infinity"`, `"-Infinity"`, `1e308` (overflow), `1e-308` (underflow)
- **Object attacks**: deeply nested objects, conflicting keys, unexpected extra fields

### T07 Auth — 13 Tests

Includes: missing auth detection, Bearer token bypass, API key abuse, HMAC signature manipulation, JWT none-algorithm attack, OAuth scope escalation, session token fixation, privilege escalation via crafted tool calls, CORS misconfiguration, rate-limit detection (429/ratelimit/throttle), protocol version abuse against all known MCP versions (`2024-11-05`, `2024-10-07`, `2025-03-26`), and duplicate `initialize()` replay with session health check.

### T06 Schema — 6 Tests

Includes a **description quality** check (T06-006) that scores tool descriptions for LLM usability:

| Finding | Severity |
|---------|----------|
| No description at all | MEDIUM |
| Useless description ("A tool", "Does stuff") | MEDIUM |
| Description under 30 characters | LOW |
| No parameter documentation signals | LOW |
| All descriptions adequate | PASS |

---

## CLI Reference

### `mcpsafe scan`

```
Usage: mcpsafe scan [OPTIONS] TARGET

Options:
  --transport  TEXT     Transport type: stdio | http  [default: stdio]
  --output     TEXT     Report format: json | html | sarif | all  [default: json]
  --timeout    INT      Per-call timeout in seconds  [default: 30]
  --modules    TEXT     Comma-separated module IDs (e.g. T01,T02,T07)
  --env        TEXT     KEY=VALUE subprocess env var, stdio only (repeatable)
  --header     TEXT     KEY=VALUE HTTP request header, http transport (repeatable)
  --config     PATH     Path to mcpsafe.toml config file
  --out-dir    PATH     Directory for output reports  [default: ./mcpsafe-reports]
  --no-load            Skip T05-003 stress test and large injection payloads
  --verbose            Print full details for every finding as they are found
```

**`--header` vs `--env`** — Use `--header` to pass HTTP request headers (Authorization, API keys) when scanning HTTP/HTTPS MCP servers. Use `--env` to set subprocess environment variables for stdio servers that read credentials from the environment.

**HTTP transport auto-detection** — MCPSafe automatically selects the right HTTP client based on the URL. URLs ending in `/mcp` use the MCP Streamable HTTP protocol (required by Cloudflare and newer servers). URLs ending in `/sse` use the legacy SSE protocol. Any other URL appends `/mcp` and tries Streamable HTTP first.

### `mcpsafe init`

Generate a commented `mcpsafe.toml` configuration file with all available options documented.

```bash
mcpsafe init                        # writes mcpsafe.toml in current directory
mcpsafe init --output /path/to/dir  # write to specific path
mcpsafe init --force                # overwrite existing file
```

MCPSafe warns if `mcpsafe.toml` contains sensitive key names (token, secret, key, password, api_key) and checks Unix file permissions (recommends `chmod 600`).

### `mcpsafe compare`

Diff two JSON reports to surface new findings and regressions between scans.

```bash
mcpsafe compare baseline.json latest.json
```

### `mcpsafe list-modules`

Show all available test modules and their test IDs.

### `mcpsafe version`

Print the MCPSafe version and exit.

---

## Output Formats

### JSON

Structured report with all findings, server metadata, and summary statistics. All server-supplied strings are sanitised (NUL bytes, ANSI escapes, control characters stripped) before serialisation.

```json
{
  "scan_id": "a1b2c3d4-...",
  "mcpsafe_version": "0.1.0",
  "started_at": "2025-01-15T10:23:45Z",
  "server_info": { "name": "mcp-server-git", "version": "0.1.0", "tool_count": 12 },
  "summary": { "total_tests": 512, "passed": 471, "failed": 41, "overall_severity": "CRITICAL" },
  "results": [ { "test_id": "T02-001", "severity": "CRITICAL", "description": "..." } ]
}
```

### HTML

Self-contained single-file report (no CDN dependencies) with a severity donut chart, per-category findings tables, and a clean dark/light design. Suitable for sharing with stakeholders or attaching to a GitHub issue.

### SARIF 2.1.0

GitHub Security tab compatible. Non-PASS findings are emitted as SARIF results.

| MCPSafe Severity | SARIF Level |
|:----------------:|:-----------:|
| CRITICAL / HIGH | `error` |
| MEDIUM | `warning` |
| LOW / INFO | `note` |
| PASS | *(omitted)* |

**GitHub Actions integration:**

```yaml
- name: Scan MCP server
  run: mcpsafe scan --transport stdio --target "uvx mcp-server-git" --output sarif --out-dir sarif-output

- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sarif-output/
```

---

## CI/CD Integration

MCPSafe exits with code `1` if CRITICAL or HIGH findings are detected, making it a natural pipeline gate.

```yaml
# .github/workflows/mcp-security.yml
name: MCP Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install MCPSafe
        run: pip install mcpsafe

      - name: Scan MCP server
        run: |
          mcpsafe scan \
            --transport stdio \
            --target "uvx mcp-server-git" \
            --output all \
            --out-dir ./mcpsafe-output

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ./mcpsafe-output/

      - name: Upload HTML report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: mcpsafe-report
          path: ./mcpsafe-output/*.html
```

---

## Example Terminal Output

```
╭─────────────────────────────────────────────╮
│ MCPSafe v0.1.0                              │
│ MCP Server Security & Stress Tester         │
╰─────────────────────────────────────────────╯

Target:     uvx mcp-server-git
Transport:  stdio
Server:     mcp-server-git v0.6.2  (protocol 2024-11-05)
Tools:      12   Resources: 0   Prompts: 0

Running 8 modules (117 tests)...

  ✓ T01 Discovery       6/6     0 findings
  ✓ T08 Latency         4/4     0 findings
  ⚠ T06 Schema          6/6     3 findings  [MEDIUM]
  ✗ T02 Injection      12/12    5 findings  [CRITICAL]
  ⚠ T03 Fuzzer         60/60   18 findings  [MEDIUM]
  ✓ T04 Tool Poison     8/8     0 findings
  ✓ T07 Auth           13/13    0 findings
  ⚠ T05 Load            8/8     4 findings  [HIGH]

┌──────────┬───────┐
│ CRITICAL │  10   │
│ HIGH     │   0   │
│ MEDIUM   │  30   │
│ LOW      │   2   │
│ INFO     │   3   │
│ PASS     │  72   │
└──────────┴───────┘

Reports saved:
  JSON → ./mcpsafe-reports/mcpsafe-mcp-server-git-a1b2c3d4-20260413-102345.json
  HTML → ./mcpsafe-reports/mcpsafe-mcp-server-git-a1b2c3d4-20260413-102345.html
  SARIF → ./mcpsafe-reports/mcpsafe-mcp-server-git-a1b2c3d4-20260413-102345.sarif

Exiting with code 1 — CRITICAL findings require attention.
```

---

## Architecture

```
mcpsafe/
├── cli.py              # click CLI: scan, init, compare, list-modules, version
├── runner.py           # async orchestration, module dispatch, rich progress
├── transport.py        # MCP connection factory (stdio / HTTP, async context managers)
├── models.py           # dataclasses: TestResult, ScanReport, ServerInfo, Severity, Category
└── tests/
│   ├── _helpers.py     # shared: sanitise_server_string, looks_like_api_rejection, timing
│   ├── t01_discovery.py
│   ├── t02_injection.py
│   ├── t03_fuzzer.py
│   ├── t04_tool_poison.py
│   ├── t05_load.py
│   ├── t06_schema.py
│   ├── t07_auth.py
│   └── t08_latency.py
└── reporter/
    ├── _common.py      # canonical server_slug() used by all reporters
    ├── json_reporter.py
    ├── html_reporter.py
    └── sarif_reporter.py
templates/
└── report.html.j2
```

**Design principles:**

- All I/O is `async/await` — no blocking calls on the event loop
- Every test returns a `TestResult` dataclass — no raw dicts cross module boundaries
- All MCP calls are wrapped in `try/except` — no test can crash the runner
- Timing is always measured in milliseconds via `time.perf_counter()`
- Server-supplied strings are sanitised at every output boundary (terminal, JSON, HTML, SARIF)

---

## Security Hardening (MCPSafe Itself)

MCPSafe is hardened against the same classes of attack it tests for:

**Rich markup injection prevention** — Server-supplied strings are passed through `rich.markup.escape()` before embedding in terminal output. A malicious server cannot inject markup into the operator's terminal.

**Immutable test results** — `HtmlReporter` uses `dataclasses.replace()` to create sanitised copies of `TestResult` objects rather than mutating originals. The source `ScanReport` is never modified, so JSON and HTML reports written sequentially are always consistent.

**Recursive JSON sanitisation** — `JsonReporter` applies `_sanitise_value()` (depth-capped at 10) before `json.dumps()`. NUL bytes, ANSI escapes, and control characters from untrusted servers cannot corrupt SIEM parsers or log aggregators.

**Per-scan state isolation** — `t08_latency.py` clears the module-level `_baseline_latencies` dict at the start of every scan, preventing timing data from a prior run leaking into sequential scans in the same process.

**Config credential warnings** — `mcpsafe init` warns if `mcpsafe.toml` contains keys matching sensitive patterns and checks Unix file permissions.

**Input validation** — `--timeout` and `--concurrency` are validated before the scan starts. `mcpsafe compare` uses a defensive `_load_report()` helper that validates JSON shape, required keys, and type-checks each result before display.

---

## Options Reference

| Option | Default | Description |
|--------|---------|-------------|
| `--transport` | `stdio` | Transport protocol: `stdio`, `http` |
| `--output` | `json` | Report format: `json`, `html`, `sarif`, `all` |
| `--modules` | all | Comma-separated module IDs to run |
| `--out-dir` | `./mcpsafe-reports` | Directory to save reports |
| `--timeout` | `30` | Seconds per MCP call before timeout |
| `--header` | — | `KEY=VALUE` HTTP request header, http transport only (repeatable) |
| `--env` | — | `KEY=VALUE` subprocess env var, stdio transport only (repeatable) |
| `--config` | — | Path to `mcpsafe.toml` |
| `--no-load` | `false` | Skip T05-003 stress test and large payloads |
| `--verbose` | `false` | Print each finding as it is discovered |

---

## Severity Levels

| Level | Meaning |
|:-----:|---------|
| **CRITICAL** | Exploitable — should block deployment |
| **HIGH** | Serious — requires prompt remediation |
| **MEDIUM** | Potential vulnerability — should be investigated |
| **LOW** | Best-practice gap or informational weakness |
| **INFO** | Neutral observation (e.g. expected rate-limit, API auth required) |
| **PASS** | Test passed — no issue found |

---

## Development

```bash
git clone https://github.com/Ravikiranbantwal/mcpsafe
cd mcpsafe
pip install -e ".[dev]"

# Run unit tests
pytest tests/ -v

# Run against a real server
mcpsafe scan "uvx mcp-server-git" --verbose
```

### Adding a Test Module

1. Create `mcpsafe/tests/t09_yourmodule.py`
2. Implement `async def run(session, server_info, config) -> list[TestResult]`
3. Register in `mcpsafe/runner.py`
4. Use test IDs in format `T09-001`, `T09-002`, …

---

## Contributing

Pull requests are welcome. Please open an issue before implementing a new test module.

- Every public function needs a docstring and type hints
- All MCP calls must be wrapped in `try/except` — never let a test crash the runner
- Run `pytest tests/` before submitting

---

## Legal / Responsible Use

> **MCPSafe is intended for use against MCP servers you own or have explicit written permission to test. Unauthorized scanning of third-party servers may violate computer fraud laws in your jurisdiction (including the CFAA in the US, the Computer Misuse Act in the UK, and equivalent legislation elsewhere). The authors accept no liability for misuse.**

Use MCPSafe responsibly:
- Only scan servers you own, operate, or have written authorisation to test
- Do not use MCPSafe against production services without the operator's consent
- Treat any findings as confidential until disclosed to the server operator

---

## License

**Polyform Noncommercial License 1.0.0** — free for personal use, academic research, open-source projects, and non-profit security work. Commercial use (paid audits, SaaS products, consulting) requires a separate license — contact [bantwalravikiran@gmail.com](mailto:bantwalravikiran@gmail.com). See [LICENSE](LICENSE) for full terms.

---

## Acknowledgements

Built on the official [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) by Anthropic. MCPSafe is an independent open-source project and is not affiliated with or endorsed by Anthropic.

SARIF output format maintained by [OASIS](https://www.oasis-open.org/committees/sarif/).
