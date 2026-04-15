# MCPSafe

[![PyPI version](https://img.shields.io/pypi/v/mcpsafe.svg)](https://pypi.org/project/mcpsafe/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Modules](https://img.shields.io/badge/modules-30-green.svg)]()
[![Tests](https://img.shields.io/badge/tests-330%2B-green.svg)]()
[![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-blueviolet)](https://sarifweb.azurewebsites.net/)

> MCP has 97 million installs. Most MCP security tools scan static config files or tool descriptions. MCPSafe is the first to connect to a live running server and test actual runtime behavior — including load testing, latency benchmarking, and cross-request data leakage under concurrency.

MCPSafe is the first open-source security and stress-testing framework for MCP (Model Context Protocol) servers. Connect it to any MCP server over stdio or HTTP and get a full audit — prompt injection, path traversal, type confusion, missing auth, load behaviour, and more — in a single command.

## 📖 Interactive Learning Guide

New to MCPSafe or want to understand how the code works? The learning guide covers every module, attack type, and code pattern — with quizzes!

👉 **[Open the MCPSafe Learning Guide](https://ravikiranbantwal.github.io/mcpsafe/mcpsafe-learning-guide.html)**

*(Or open `mcpsafe-learning-guide.html` locally — it's fully self-contained, no internet required.)*

---

## Why MCPSafe?

Most MCP security tools analyze tool descriptions statically.
MCPSafe connects to your live running server and tests actual
runtime behavior.

| Approach | Tools | MCPSafe |
|---|---|---|
| Static description analysis | Snyk Agent Scan, Proximity | ✅ via T04 |
| Live adversarial payload testing | mcpwn | ✅ via T02/T03 |
| Load & concurrency testing | Nobody | ✅ via T05 |
| Latency benchmarking | Nobody | ✅ via T08 |
| Cross-request data leakage | Nobody | ✅ via T05-001 |
| JSON Schema validation | Nobody | ✅ via T06 |
| **Reverse prompt-injection (tool output poisoning)** | **Nobody** | **✅ via T09** |
| **Cross-session data leakage (multi-tenant bleed)** | **Nobody** | **✅ via T10** |
| **Timing side-channel enumeration** | **Nobody** | **✅ via T11** |
| **Error-message secret leakage (15 patterns)** | **Nobody** | **✅ via T12** |
| **Server-initiated sampling abuse** | **Nobody** | **✅ via T13** |
| **Notification-flood DoS** | **Nobody** | **✅ via T14** |
| **Concurrent-call reentrancy (state bleed)** | **Nobody** | **✅ via T15** |
| **Silent capability creep** | **Nobody** | **✅ via T16** |
| **Cross-session SHA-256 description drift** | **Nobody** | **✅ via T17** |
| **SSRF via resource URIs (10 payloads)** | **Nobody** | **✅ via T18** |
| **Unicode homoglyph tool impersonation** | **Nobody** | **✅ via T19** |
| **Server-side memory-leak detection** | **Nobody** | **✅ via T20** |
| **Deep path traversal (12 encodings)** | **Nobody** | **✅ via T21** |
| **Shell command injection (10 primitives)** | **Nobody** | **✅ via T22** |
| **Deep SQLi — UNION / blind / time-based** | **Nobody** | **✅ via T23** |
| **Insecure deserialisation (pickle/YAML/XML/Java/Ruby)** | **Nobody** | **✅ via T24** |
| **IDOR probing (resource URI substitution)** | **Nobody** | **✅ via T25** |
| **SSTI (Jinja/Twig/ERB/Velocity/Razor)** | **Nobody** | **✅ via T26** |
| **Session token entropy + reuse + leak** | **Nobody** | **✅ via T27** |
| **CRLF / header injection + smuggling** | **Nobody** | **✅ via T28** |
| **ReDoS (regex DoS) with baseline comparison** | **Nobody** | **✅ via T29** |
| **OAuth flow abuse (redirect URI, state)** | **Nobody** | **✅ via T30** |
| SARIF for GitHub Security tab | Nobody (yet) | ✅ |
| Regression tracking (compare) | Nobody | ✅ |
| No account or API key needed | mcpwn only | ✅ |
| Rate-limit-aware pacing for auth-gated APIs | Nobody | ✅ |

---

## Real-World Results

MCPSafe v0.3.0 audited **13 MCP servers** — including Stripe's, Cloudflare's, GitHub's, and Anthropic's reference servers. The numbers below are the validated counts after the v0.3.0 noise-reduction pass:

- **T22 Command Injection** — removed newline & NUL primitives (unreliable under JSON-escape echoing); added JSON-unicode-escape stripping and an `echo`-prefix guard so a transformed echo of our payload no longer reads as canary survival.
- **T24 Deserialisation** — payloads whose canary lives inside the payload (`DS-002`, `DS-003`, `DS-008`) skip the canary-survives-CRITICAL path and rely on error-marker LOW detection; they cannot reliably be distinguished from echoes.
- **T02 Injection** — private-range IPv4 regex suppressed on pass-through content tools (`search_*`, `list_*`, `fetch`, `read_*`, `get_*`, …) where private IPs are user-authored content rather than internal leaks.
- **T30 OAuth** — open-redirect check compares the Location URL's hostname via `urlparse`, not a substring of the raw header, so legitimate login redirects with an authorize-URL in a query param no longer flag CRITICAL.
- **T28 Header Injection** — JSON-escape-aware payload strip plus an in-JSON-value gate so an injected header name echoed inside a product/field name is no longer flagged as a real CRLF injection.
- **T16 / T17 Capability Creep** — auto-generator noise filter: when ≥ 5 newly added resources share ≤ 2 namespace prefixes, downgrade MEDIUM → LOW with a "likely auto-generator or side-effect" label.
- **T03 Fuzzer** — `trigger-long-running-operation` / sleep / wait / delay tools are now skipped, eliminating the 35-second timeout false-positives.

**9,341 tests across 30 modules · 0 CRITICAL · 29 HIGH · 522 MEDIUM · 79 LOW · 13 INFO · 8,698 PASS**

| Server | Transport | CRITICAL | HIGH | MEDIUM | Notable Finding |
|--------|-----------|:--------:|:----:|:------:|-----------------|
| `@modelcontextprotocol/server-everything` | stdio | — | **14** | 70 | Stored PI via `args-prompt` (14 HIGH — every PI-### payload echoed verbatim into LLM messages) |
| `mcp-server-sqlite` *(uvx)* | stdio | — | **14** | 8 | Stored PI via `mcp-demo` prompt template |
| `mcp.stripe.com` *(auth)* 💳 | HTTP | — | — | 170 | Injection echoes across `create_refund`, `cancel_subscription`, `list_payment_intents` |
| `mcp-server-fetch` *(uvx)* | stdio | — | — | 3 | — |
| `mcp_text_processor` *(test)* | stdio | — | **1** | 42 | `extract_emails` hard-timed out on 100 KB payload (resource-exhaustion DoS) |
| `@modelcontextprotocol/server-filesystem` | stdio | — | — | 91 | Injection echoes in OS error messages |
| `@modelcontextprotocol/server-github` *(auth)* | stdio | — | — | 3 | Injection echoes in `search_issues` results |
| `mcp-server-git` *(uvx)* | stdio | — | — | 59 | Git error messages echo injection payloads |
| `mcp_calculator` *(test)* | stdio | — | — | 21 | — |
| `mcp_notes` *(test)* | stdio | — | — | 38 | — |
| `mcp-server-time` *(uvx)* | stdio | — | — | 14 | — |
| `docs.mcp.cloudflare.com` *(auth)* | HTTP | — | — | 2 | — |
| `observability.mcp.cloudflare.com` *(auth)* | HTTP | — | — | 1 | — |

### Selected Findings

**`@modelcontextprotocol/server-everything` (Anthropic's reference server)** — **14 HIGH, 0 CRITICAL**. All 14 HIGHs are stored-prompt-injection findings on the `args-prompt` prompt template, which embeds raw argument values directly into generated LLM messages. Every PI-001..PI-016 payload landed in the model's context window verbatim — a textbook stored-injection surface.

**`mcp-server-sqlite` (uvx)** — **14 HIGH**, all from the `mcp-demo` prompt template. The prompt embeds raw argument values into generated messages without sanitisation. Every PI-001..PI-016 payload becomes a stored prompt injection landing in the LLM context window.

**`mcp.stripe.com` (Stripe Payments, live HTTP, auth)** — **170 MEDIUM**. Stripe's production server echoes injection payloads verbatim across every financial tool — `create_refund`, `cancel_subscription`, `create_invoice`, `list_payment_intents`, and more. Any LLM consuming Stripe tool output is a prompt-injection attack surface.

**`@modelcontextprotocol/server-filesystem`** — **91 MEDIUM** injection echoes across file-path tools (`read_file`, `write_file`, `list_directory`). The tools pass raw argument strings to OS syscalls; malformed paths return OS errors containing the injection payload verbatim.

**`@modelcontextprotocol/server-github`** — **3 MEDIUM** injection echoes via `search_issues`. The tool passes user `query` strings to GitHub's API, which returns search results verbatim. An LLM reading the output could follow injected instructions — MEDIUM because the echo is bounded by the API's search response shape.

**`mcp_text_processor` (test server)** — **1 HIGH**: `extract_emails` hard-timed out on a 100 KB payload — real resource-exhaustion DoS.

**`observability.mcp.cloudflare.com` (Cloudflare, live HTTP, auth)** — **1 MEDIUM**. T04-001 detected description growth between calls — consistent with CDN edge truncation, correctly classified as MEDIUM (not a deliberate rug-pull).

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

MCPSafe v0.3.1 runs **330+ test types** across **30 modules** covering discovery, security, performance, and schema validation.

### Core Modules (T01–T08) — Foundation

| Module | Category | What It Checks |
|--------|----------|----------------|
| **T01** Discovery | DISCOVERY | Server enumeration, tool listing, resource/prompt exposure, metadata consistency |
| **T02** Injection | SECURITY | 16 prompt injection payloads per string parameter — classic overrides, SQL probes, shell metacharacters, Unicode RLO, path traversal, Jinja / Python format injections |
| **T03** Fuzzer | SECURITY | Type confusion, boundary values, oversized payloads, deep nesting, NaN/Infinity across every tool parameter |
| **T04** Tool Poison | SECURITY | Tool description mutation (rug-pull attacks), baseline drift, hidden instructions. Growth-only vs true-mutation classification eliminates CDN truncation false positives |
| **T05** Load | PERFORMANCE | Concurrent load (10/50/100 calls), cross-request UUID leakage detection, reconnect stability |
| **T06** Schema | SCHEMA | JSON Schema validation, required field enforcement, description quality scoring |
| **T07** Auth | SECURITY | Missing auth, Bearer bypass, protocol version abuse, replay attacks, homoglyph tool name spoofing |
| **T08** Latency | PERFORMANCE | Baseline latency, P95/P99 percentiles, cold-start detection, post-load degradation |

### New in v0.2.0 (T09–T20) — Advanced Attack Surfaces

Features found in **no other MCP security tool**:

| Module | Category | What It Checks |
|--------|----------|----------------|
| **T09** Output Sanitization | SECURITY | **Reverse prompt injection** — scans *tool output* for PI markers that would poison the next LLM call. Skips pass-through tools (file/diff/fetch/search) to avoid false positives on data content |
| **T10** Cross-Session Leakage | SECURITY | Plants a unique marker via session A, opens an independent session B, checks if B sees A's data — detects shared cache/global-state multi-tenancy failures |
| **T11** Timing Side-Channel | SECURITY | Statistical timing comparison of plausible-vs-random inputs. Trimmed means + 5× ratio + 30 ms absolute threshold to detect enumeration oracles without jitter FPs |
| **T12** Error Secret Leakage | SECURITY | Triggers malformed-argument error paths and scans output for 15 secret patterns: AWS / GitHub / OpenAI / Anthropic / Stripe keys, JWTs, Bearer tokens, DB URIs, `/etc/passwd`, env vars, private IPs |
| **T13** Sampling Abuse | SECURITY | Audits `sampling` capability advertisement and attempts to detect unsolicited server → client sampling requests during tool execution |
| **T14** Notification Flood | SECURITY | Monitors inbound notifications during a 5 s quiet window. Flags >5/sec as MEDIUM, >30 total as HIGH — client-side DoS |
| **T15** Reentrancy | SECURITY | 6 concurrent calls with unique markers; any response containing a marker the caller didn't send = shared-state bug |
| **T16** Capability Creep | SECURITY | Snapshots tools / resources / prompts / capabilities at T=0 and T=3 s; any silent addition or removal is flagged |
| **T17** Hash Drift | SECURITY | SHA-256 fingerprint of every tool/resource/prompt description. Compares across two independent sessions — catches per-connection A/B testing (rug-pull precursor) |
| **T18** Resource URI SSRF | SECURITY | 10 malicious URIs fed to `read_resource`: AWS / GCP / Azure metadata, `file://`, loopback (Redis, Elasticsearch), SSH keys, DNS-rebind probes |
| **T19** Unicode Homoglyph | SECURITY | Confusable characters (Cyrillic / Greek / fullwidth), mixed-script identifiers, invisible controls (ZWSP, BOM, RLO). Only flags HIGH when the name collapses to an existing ASCII identifier — no false positives on legitimate i18n |
| **T20** Memory Leak | PERFORMANCE | 40-call probe; trimmed-quartile response-size and latency drift analysis + subprocess RSS growth (stdio + psutil) |

### New in v0.3.0 (T21–T30) — Classic Web Security Classes, Applied to MCP

These are **CVE-class** attack surfaces — the same categories that OWASP Top 10 covers, mapped to MCP's tool + resource interfaces. Bug bounty programs pay for findings in these classes:

| Module | Category | What It Checks |
|--------|----------|----------------|
| **T21** Path Traversal Deep | SECURITY | 12 traversal encodings (URL / double-URL / UTF-8-overlong / Unicode slash / NUL truncation / absolute paths) against every path-like parameter. Detects actual `/etc/passwd`, `win.ini`, `/proc/self/environ` content in responses — CRITICAL when confirmed |
| **T22** Command Injection | SECURITY | 8 shell-metacharacter primitives (`;`, `\|`, `&`, `&&`, `\|\|`, `$()`, backticks, Windows cmd chain) with per-call random canaries. CRITICAL when canary survives JSON-unicode-escape stripping AND is not preceded by `echo ` — proves real shell evaluation, not echo of payload |
| **T23** SQL Injection Deep | SECURITY | Beyond T02's quote probe: UNION version extraction, boolean-based blind, time-based blind (pg_sleep/WAITFOR/SLEEP), MongoDB `$ne`/`$gt`. CRITICAL on UNION data extraction, HIGH on time-based |
| **T24** Insecure Deserialisation | SECURITY | Python pickle / PyYAML `!!python/object` / XML XXE / Java ObjectInputStream magic / Ruby Marshal / prototype pollution. Canary-based execution detection — CRITICAL on real RCE for primitives where the canary is OUTSIDE the payload (pickle / XXE / Java / Ruby); LOW error-marker detection only for primitives where the canary lives INSIDE the payload (YAML apply, `__proto__`) since echo cannot be reliably distinguished from execution |
| **T25** IDOR | SECURITY | Numeric ID increment / decrement, user-token substitution (`user` → `admin`, `me` → `root`) in resource URIs. HIGH when forged URI returns non-trivial content not in the advertised list |
| **T26** SSTI | SECURITY | 10 template primitives (Jinja/Twig `{{7*7}}`, ERB `<%=`, Freemarker `${}`, Velocity `#set`, Razor `@()`, Mako, Smarty). Marker-bracketed detection — CRITICAL on evaluation |
| **T27** Session Token Handling | SECURITY | Token reuse after close, Shannon-entropy check (< 2 bits/char = MEDIUM), token leak into tool responses (HIGH) |
| **T28** Header Injection | SECURITY | CRLF / URL-encoded / Unicode newline injection with distinctive header name. HIGH when `X-MCPSafe-Injected` survives JSON-escape-aware payload-stripping AND is NOT inside a JSON string value (gates against echo-as-field-value FPs) |
| **T29** ReDoS | SECURITY | 5 catastrophic-backtracking patterns vs benign baseline. MEDIUM on 5× ratio + 3s delta, HIGH when attack input hits the 30s client timeout |
| **T30** OAuth Flow Abuse | SECURITY | `.well-known/oauth-authorization-server` discovery → redirect-URI spoof test → state-parameter entropy. CRITICAL only when the Location URL's HOSTNAME is attacker-controlled (urlparse-based check) — substring matches on attacker URLs embedded as query params of legitimate hosts no longer fire |

### Real Vulnerabilities MCPSafe Catches

**Stored prompt injection via tool output** (T02, T09) — Every string passed to a tool parameter gets bounced back through 16 attack payloads (PI-001..PI-016). If any payload appears verbatim in the response, the test flags it. Confirmed on **server-everything**, **sqlite**, **server-filesystem**, **server-github**, **mcp-server-git**, and **mcp.stripe.com**.

**Prompt template injection** (T02, stored PI) — Prompts like `args-prompt` on server-everything and `mcp-demo` on sqlite embed raw argument values into LLM messages. **14 HIGH findings per server** — every payload lands in the AI's context window verbatim.

**Tool description rug-pull attacks** (T04, documented by Invariant Labs 2025) — Tool description mutates silently between `list_tools()` calls. Growth-only mutations are correctly downgraded to MEDIUM to avoid CDN truncation false positives.

**DoS via large payloads** (T02) — Confirmed on `mcp-text-processor`'s `extract_emails` (100 KB payload triggers hard 10s timeout) and on `mcp-server-sqlite`'s tool surface (14 HIGH findings via large-input timeouts). Tools that are intentionally long-running (e.g. `trigger-long-running-operation`) are skipped from fuzzing to avoid documented-behaviour false positives.

**Cross-request data leakage under concurrency** (T05-001) — Embeds unique UUIDs in 10 concurrent calls; if call A's response contains call B's UUID, shared state is leaking between parallel requests. Same class as MCP TypeScript SDK CVE (CVSS 7.1).

**SSRF via resource URIs** (T18) — Feeds `file:///etc/passwd`, AWS metadata IP `169.254.169.254`, and 8 other malicious URIs to `read_resource`. CRITICAL when the response content actually matches metadata/file format.

**Error message secret leakage** (T12) — Catches servers that stringify DB connection strings, env vars, API keys, or JWTs into exception messages — 15-pattern regex library with value redaction in reports.

### T03 Fuzzer — Fuzz Case Corpus

- **String attacks**: null bytes, Unicode overlong sequences, ANSI escapes, format strings (`%s %n`), 1 MB payloads
- **Integer boundary**: `MAX_INT32+1`, `MIN_INT32-1`, beyond int64 (`9_223_372_036_854_775_808`), zero, negatives
- **Type confusion**: strings where integers expected (`"NaN"`, `"Infinity"`, `"-1"`), objects in array slots
- **Array attacks**: 10,000-element array, mixed-type array (1,000 elements), 100-level deep nested array
- **Number edge cases**: `"NaN"`, `"Infinity"`, `"-Infinity"`, `1e308` (overflow), `1e-308` (underflow)
- **Object attacks**: deeply nested objects, conflicting keys, unexpected extra fields

### T07 Auth — Authentication & Protocol Tests

Missing auth detection, Bearer token bypass, API key abuse, JWT none-algorithm attack, OAuth scope escalation, session token fixation, rate-limit detection (429/ratelimit/throttle), protocol version abuse against all known MCP versions (`2024-11-05`, `2024-10-07`, `2025-03-26`), duplicate `initialize()` replay with session health check, and Unicode homoglyph tool-name spoofing.

### T06 Schema — Description Quality Scoring

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
  "mcpsafe_version": "0.3.1",
  "started_at": "2026-04-15T09:47:04Z",
  "server_info": { "name": "mcp-server-git", "protocol_version": "2024-11-05", "tool_count": 12 },
  "summary": { "total_tests": 832, "passed": 762, "failed": 70, "overall_severity": "MEDIUM" },
  "results": [ { "test_id": "T02-001", "severity": "MEDIUM", "description": "..." } ]
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
│ MCPSafe v0.3.1                              │
│ MCP Server Security & Stress Tester         │
╰─────────────────────────────────────────────╯

Target:     uvx mcp-server-git --repository .
Transport:  stdio
Server:     mcp-server-git  (protocol 2024-11-05)
Tools:      12   Resources: 0   Prompts: 0

Running 30 modules (830+ tests)...

  ✓ T01 Discovery              100%  0:00:00
  ✓ T08 Latency Baseline       100%  0:00:00
  ✓ T06 Schema                 100%  0:00:00
  ⚠ T02 Injection              100%  0:00:15   [MEDIUM]
  ✓ T03 Fuzzer                 100%  0:00:01
  ✓ T04 Tool Poison            100%  0:00:13
  ✓ T09 Output Sanitization    100%  0:00:06
  ✓ T12 Error Secret Leakage   100%  0:00:14
  ✓ T13 Sampling Abuse         100%  0:00:07
  ⚠ T16 Capability Creep       100%  0:00:14   [MEDIUM]
  ✓ T18 SSRF                   100%  0:00:00
  ⚠ T19 Homoglyph              100%  0:00:00   [MEDIUM]
  ✓ T21 Path Traversal         100%  0:00:10
  ✓ T22 Command Injection      100%  0:00:08
  ✓ T23 SQL Injection Deep     100%  0:00:10
  ⚠ T24 Deserialization        100%  0:00:08   [LOW]
  ✓ T25 IDOR                   100%  0:00:00
  ✓ T26 SSTI                   100%  0:00:08
  ✓ T28 Header Injection       100%  0:00:00
  ✓ T30 OAuth Flow             100%  0:00:00
  ⚠ T07 Auth                   100%  0:00:08   [MEDIUM]
  ✓ T11 Timing Side-Channel    100%  0:00:00
  ✓ T15 Reentrancy             100%  0:00:00
  ✓ T29 ReDoS                  100%  0:00:01
  ✓ T27 Session Tokens         100%  0:00:00
  ⚠ T05 Load                   100%  0:00:13   [MEDIUM]
  ✓ T10 Cross-Session Leakage  100%  0:00:01
  ✓ T17 Hash Drift             100%  0:00:01
  ✓ T14 Notification Flood     100%  0:00:05
  ✓ T20 Memory Leak            100%  0:00:00
  ✓ T08-005 Latency Comparison 100%  0:00:00

┌──────────┬───────┐
│ CRITICAL │   0   │
│ HIGH     │   0   │
│ MEDIUM   │  59   │
│ LOW      │  10   │
│ INFO     │   1   │
│ PASS     │ 762   │
└──────────┴───────┘

Reports saved:
  JSON  → ./mcpsafe-reports/mcpsafe-git-20260414-091438.json
  HTML  → ./mcpsafe-reports/mcpsafe-git-20260414-091438.html
  SARIF → ./mcpsafe-reports/mcpsafe-git-20260414-091438.sarif

Exit 0 — no CRITICAL or HIGH findings.
```

---

## Architecture

```
mcpsafe/
├── cli.py              # click CLI: scan, init, compare, list-modules, version
├── runner.py           # async orchestration, module dispatch, rich progress
├── transport.py        # MCP connection factory (stdio / HTTP, async context managers)
├── models.py           # dataclasses: TestResult, ScanReport, ServerInfo, Severity, Category
├── tests/
│   ├── _helpers.py     # RateLimiter, SECRET_PATTERNS, cap_response, sanitise_server_string
│   ├── t01_discovery.py            # T01 — capability enumeration
│   ├── t02_injection.py            # T02 — prompt injection payloads
│   ├── t03_fuzzer.py               # T03 — malformed input fuzzing
│   ├── t04_tool_poison.py          # T04 — rug-pull mutation detection
│   ├── t05_load.py                 # T05 — load / concurrency / UUID leakage
│   ├── t06_schema.py               # T06 — JSON Schema validation
│   ├── t07_auth.py                 # T07 — auth / protocol / replay tests
│   ├── t08_latency.py              # T08 — latency benchmarks
│   ├── t09_output_sanitization.py  # T09 — reverse PI detection ✨ v0.2.0
│   ├── t10_cross_session.py        # T10 — cross-session data leakage ✨
│   ├── t11_timing_side_channel.py  # T11 — timing enumeration oracles ✨
│   ├── t12_secret_leakage.py       # T12 — 15 secret patterns in errors ✨
│   ├── t13_sampling_abuse.py       # T13 — server-initiated sampling ✨
│   ├── t14_notification_flood.py   # T14 — client-side DoS ✨
│   ├── t15_reentrancy.py           # T15 — concurrent-call state bleed ✨
│   ├── t16_capability_creep.py     # T16 — silent inventory drift ✨
│   ├── t17_hash_drift.py           # T17 — SHA-256 cross-session fingerprints ✨
│   ├── t18_ssrf.py                 # T18 — resource URI SSRF (10 payloads) ✨
│   ├── t19_homoglyph.py            # T19 — Unicode confusables ✨
│   ├── t20_memory_leak.py          # T20 — RSS / latency / size drift ✨
│   ├── t21_path_traversal.py       # T21 — 12 traversal encodings ✨ v0.3.0
│   ├── t22_command_injection.py    # T22 — shell-metachar canary tests ✨
│   ├── t23_sql_injection.py        # T23 — UNION / boolean / time-based SQLi ✨
│   ├── t24_deserialization.py     # T24 — pickle / YAML / XXE / Java magic ✨
│   ├── t25_idor.py                 # T25 — resource URI ID substitution ✨
│   ├── t26_ssti.py                 # T26 — Jinja / ERB / Velocity / Razor ✨
│   ├── t27_session_token.py        # T27 — token entropy / reuse / leak ✨
│   ├── t28_header_injection.py     # T28 — CRLF / Unicode newline injection ✨
│   ├── t29_redos.py                # T29 — catastrophic-backtracking DoS ✨
│   └── t30_oauth_flow.py           # T30 — OAuth redirect-URI / state ✨
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

1. Create `mcpsafe/tests/t31_yourmodule.py` (next available number after T30)
2. Implement `async def run(session, server_info, config) -> list[TestResult]`
3. Register in `mcpsafe/runner.py` (both the import block and the execution plan)
4. Use test IDs in format `T31-001`, `T31-002`, …
5. Return `TestResult` dataclasses — never raise exceptions; catch everything and wrap with `TestResult.from_exception()`
6. If your module needs rate limiting on auth-gated HTTP servers, use `RateLimiter(config)` from `mcpsafe.tests._helpers`

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

**MIT License** — free for personal, commercial, academic, and open-source use. Just keep the copyright notice intact. See [LICENSE](LICENSE) for full terms.

---

## Acknowledgements

Built on top of the official **[Model Context Protocol](https://modelcontextprotocol.io)** SDK from Anthropic, plus [httpx](https://www.python-httpx.org/), [click](https://click.palletsprojects.com/), [rich](https://rich.readthedocs.io/), [jinja2](https://jinja.palletsprojects.com/), and [anyio](https://anyio.readthedocs.io/).

Prior art and inspiration:
- Invariant Labs — original rug-pull / tool description mutation research
- The OWASP AI Security & Privacy Guide
- The broader MCP security research community

If you use MCPSafe in research, please cite this repository.
