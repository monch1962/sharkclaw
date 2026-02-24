You are Opencode. Implement a production-quality Go CLI tool named `sharkclaw` that detects and counts “weird” network behaviors indicative of attacks and/or network problems. The tool must analyze either a PCAP/PCAPNG file or perform a short live capture and then analyze. The tool will be called by an AI tool (e.g., OpenClaw), so its output must be stable, machine-readable JSON ONLY (no human text/logs on stdout or stderr).

NON-NEGOTIABLE REQUIREMENTS
1) Language: Go (latest stable).
2) Binary: single-binary CLI named `sharkclaw`.
3) Modes:
   - PCAP analysis: user supplies a PCAP or PCAPNG file.
   - Live capture: capture traffic for a configurable duration (default 10 seconds), then analyze.
4) Weird behaviors (core required):
   - High-latency traffic flows (using TCP handshake RTT and DNS RTT).
   - TCP reliability hints (at minimum: retransmissions, duplicate ACKs; optionally out-of-order segments if feasible).
   - TCP resets.
   - Incomplete TCP handshakes.
   - DNS failures (NXDOMAIN, SERVFAIL, timeouts/no-response).
5) Output: valid JSON ONLY. No other output. No log lines. No progress messages.
6) Exit codes:
   - 0 when the tool runs successfully, regardless of findings severity.
   - non-zero only for tool errors (invalid args, file not found, parse failure, permission error, capture failure).
7) `--help` / `-h`: must exist and be detailed, but must not print plain text by default output rules.
   - Implement `--help` as JSON output too (see “help JSON schema”), so the “only JSON” rule is maintained.
8) Stable JSON schema over time:
   - include schema_version at top level (semantic version string).
   - never remove or rename keys once released; only add new optional fields.
   - always include the top-level objects with default/zero values.
9) TDD mandatory:
   - write tests FIRST for every feature.
   - maintain high test coverage for parsing, metrics, thresholds, and JSON output.
   - CI-like command: `go test ./...` must pass.
   - use table-driven tests and golden JSON fixtures where appropriate.

DELIVERABLES (Repo structure)
- cmd/sharkclaw/main.go
- internal/cli (cobra/urfave or stdlib flags; choose one and document)
- internal/capture (live capture via gopacket/pcap)
- internal/pcap (pcap reader using gopacket)
- internal/analyze (flow tracking + metrics computation)
- internal/schema (types for stable JSON schema + versioning)
- internal/thresholds (default thresholds/profiles)
- internal/output (JSON encoding, stable ordering if possible, golden tests)
- README.md:
  - What it does, supported signals, examples (with sample JSON snippets)
  - operational notes about privileges for capture mode
  - schema versioning policy
- Makefile (optional) with `test`, `lint` (if you add golangci-lint, vendor config)
- Provide a small test PCAP/PCAPNG fixture set (very small) generated in tests or embedded as bytes; or build synthetic packets in tests if easier.
  - Do NOT require external downloads.

TOOL UX (CLI SPEC)
Command forms (must implement):
1) PCAP mode:
   sharkclaw pcap --file <path> [--filter <bpf>] [--profile lan|wan] [--pretty] [--include-topN <n>]
2) Capture mode:
   sharkclaw capture [--duration <seconds|GoDuration>] [--iface <name>] [--filter <bpf>] [--profile lan|wan] [--pretty] [--include-topN <n>]
3) Help:
   sharkclaw --help
   sharkclaw -h
   sharkclaw help
All help must emit JSON (see below), and must still return exit code 0.

Flags and defaults:
- --duration: default "10s" (accept Go duration format; also accept integer seconds).
- --iface:
  - default: "any" on Linux where supported; otherwise require explicit --iface or fall back to first non-loopback interface (document behavior). Choose a deterministic default and test it.
- --filter: optional BPF string. If absent, capture all.
- --profile: default "wan". Profiles affect high-latency thresholds primarily.
- --pretty: if set, output indented JSON.
- --include-topN: default 5. Include top talkers arrays limited to N (0 disables).
- The tool MUST NOT write to files.

ONLY JSON OUTPUT RULE
- stdout: JSON only.
- stderr: ideally nothing. If you must output errors, emit JSON to stdout and keep stderr empty; return non-zero.
- On errors, still output a JSON object in the same schema, but include an `errors` array with details.

DETECTION / ANALYSIS REQUIREMENTS
You must compute metrics from packets and reconstruct enough state to detect:
A) Incomplete TCP handshakes:
- Count SYN packets that do not result in a completed 3-way handshake (SYN, SYN-ACK, ACK) within the capture/pcap time window.
- Track per 4-tuple (src ip, src port, dst ip, dst port).
- Consider retransmitted SYNs: treat as same handshake attempt if seq/tuple match.
- Report:
  - count_incomplete_handshakes
  - syn_total
  - completion_rate
  - severity

B) TCP resets:
- Count RST flags per flow.
- Report count and rate per 1k TCP flows.

C) TCP reliability hints:
- Retransmissions: detect by repeated sequence numbers with overlapping payload ranges for a flow (approximation acceptable).
- Duplicate ACKs: detect repeated ACK numbers without forward progress, per flow.
- Out-of-order segments: optional; if implemented, count.
- Report counts and rates.

D) High-latency flows:
- TCP handshake RTT: time delta between SYN and SYN-ACK for successful handshakes.
- DNS RTT: time delta between DNS query and response (match by transaction ID + tuple).
- Report distribution stats: p50, p95, p99 (ms) for each latency type.
- Define “high latency” as p95 above threshold OR count of events above threshold; include both raw counts and computed severity.

E) DNS failures:
- NXDOMAIN: response RCODE=3
- SERVFAIL: RCODE=2
- Timeout/no-response: query with no response within a window (e.g., 2s LAN, 5s WAN by profile; configurable in thresholds package)
- Report counts and rates.

F) Additional suggested “attack/ops” indicators (implement at least 2, with stable schema):
1) SYN-scan indicator:
   - high SYN rate from a src IP with low handshake completion rate
   - report top suspected scanners (src ip + syn count + completed count)
2) DNS anomaly:
   - elevated NXDOMAIN rate per client
   - report top clients

You can add more counters, but keep schema stable: include fields even if zero.

THRESHOLDS & SEVERITY
Implement a deterministic severity scoring per signal:
- severity levels: "info", "low", "medium", "high", "critical"
- Provide default thresholds for both profiles:
  - profile=lan: stricter RTT expectations, shorter DNS timeout window
  - profile=wan: looser RTT expectations, longer DNS timeout window
Example default threshold guidance (refine as you implement):
- handshake_rtt_ms p95:
  - lan: medium if > 200ms, high if > 500ms, critical if > 1200ms
  - wan: medium if > 800ms, high if > 1500ms, critical if > 3000ms
- dns_rtt_ms p95:
  - lan: medium if > 150ms, high if > 400ms, critical if > 1000ms
  - wan: medium if > 400ms, high if > 900ms, critical if > 2000ms
- incomplete handshakes:
  - medium if incomplete_syn > 20 AND incomplete_rate > 5%
  - high if > 100 OR rate > 15%
- tcp resets:
  - medium if rst_count > 10 AND rst_rate_per_1k_flows > 5
  - high if rst_count > 50 OR rst_rate_per_1k_flows > 20
- retransmissions rate:
  - medium if > 2%
  - high if > 8%
- dns failures:
  - medium if failure_count > 5 AND failure_rate > 2%
  - high if > 20 OR rate > 10%
The exact numbers can be adjusted, but must be documented and tested.

Overall summary severity:
- The top-level summary.severity should be the maximum severity among signals.
- summary.signals_triggered = number of signals whose severity >= "medium" (or define your rule and document).

JSON SCHEMA (v1.0.0)
Implement these top-level keys exactly; all must always exist:

{
  "schema_version": "1.0.0",
  "tool": { "name": "sharkclaw", "version": "<semver>" },
  "run": {
    "mode": "pcap" | "capture" | "help",
    "start_time": "<RFC3339>",
    "end_time": "<RFC3339>",
    "duration_seconds": <number>,
    "input": { "pcap_file": "<string or empty>" },
    "capture": { "iface": "<string or empty>", "bpf": "<string or empty>" },
    "profile": "lan" | "wan"
  },
  "summary": {
    "severity": "info|low|medium|high|critical",
    "signals_triggered": <int>
  },
  "metrics": {
    "flows_total": <int>,
    "tcp": {
      "syn_total": <int>,
      "incomplete_handshakes": { "count": <int>, "rate_percent": <float>, "severity": "<level>" },
      "resets": { "count": <int>, "rate_per_1k_flows": <float>, "severity": "<level>" },
      "reliability_hints": {
        "retransmissions": { "count": <int>, "rate_percent": <float>, "severity": "<level>" },
        "dup_acks": { "count": <int>, "rate_percent": <float>, "severity": "<level>" },
        "out_of_order": { "count": <int>, "rate_percent": <float>, "severity": "<level>" }
      },
      "latency": {
        "handshake_rtt_ms": { "p50": <int>, "p95": <int>, "p99": <int>, "above_threshold": <int>, "severity": "<level>" }
      }
    },
    "dns": {
      "queries": <int>,
      "failures": { "count": <int>, "rate_percent": <float>, "severity": "<level>" },
      "nxdomain": { "count": <int>, "rate_percent": <float> },
      "servfail": { "count": <int>, "rate_percent": <float> },
      "timeouts": { "count": <int>, "rate_percent": <float> },
      "latency_rtt_ms": { "p50": <int>, "p95": <int>, "p99": <int>, "above_threshold": <int>, "severity": "<level>" }
    },
    "anomalies": {
      "syn_scan_suspects": { "count": <int>, "top": [ { "ip": "<string>", "syn": <int>, "completed": <int>, "completion_rate_percent": <float> } ] },
      "dns_nxdomain_clients": { "count": <int>, "top": [ { "ip": "<string>", "queries": <int>, "nxdomain": <int>, "nxdomain_rate_percent": <float> } ] }
    }
  },
  "top_talkers": {
    "sources": [ { "ip": "<string>", "new_connections": <int>, "bytes": <int> } ],
    "destinations": [ { "ip": "<string>", "new_connections": <int>, "bytes": <int> } ]
  },
  "errors": [ { "code": "<string>", "message": "<string>", "details": "<string optional>" } ],
  "help": { ... } // present always; empty object unless mode=help
}

HELP JSON SCHEMA
When user runs `sharkclaw --help` or `sharkclaw help`, output the SAME top-level schema above but with:
- run.mode="help"
- help populated, including:
  - description (what the tool does)
  - commands list with names and examples
  - flags list with descriptions and defaults
  - signals list and what they mean
No plain text.

IMPLEMENTATION GUIDANCE
- Use gopacket for parsing packets (pcap and pcapng) and live capture.
- Flow tracking:
  - create a stable key type for 4-tuple + protocol.
  - keep minimal state to detect handshake completion and compute RTTs.
  - track timestamps for SYN and SYN-ACK.
  - for retrans/dup-ack heuristics, store recent sequence/ack numbers per flow with a bounded LRU/ring buffer to avoid memory blowups.
- DNS parsing:
  - use gopacket layers.DNS when present.
  - match query/response by (client ip, server ip, client port, server port, txid, qname) if available; at minimum txid + tuple.
  - maintain a pending map of queries with timestamps; expire after timeout window (profile dependent) and count as timeout failures.
- Rates:
  - rate_percent = count / denom * 100 (guard divide-by-zero).
  - flows_total should be computed as unique TCP flows observed (or include UDP flows too; choose and document; tests must reflect chosen definition).
- Top talkers:
  - compute bytes per src/dst, and new_connections per src/dst (TCP SYN seen as connection attempt).
  - limit arrays to include-topN.

TDD PLAN (MANDATORY)
Implement in small increments with tests before code:
1) Schema types + JSON output:
   - tests that output JSON always includes required keys.
   - golden tests for pretty vs compact.
2) CLI parsing:
   - tests for each command/flag combination.
   - tests that `--help` emits JSON help schema.
3) PCAP reader minimal:
   - tests using synthetic packets (preferred) or tiny embedded pcap fixture.
4) TCP handshake detection:
   - tests for complete handshake, incomplete handshake, retransmitted SYNs.
5) TCP RST counter tests.
6) DNS parsing + NXDOMAIN/SERVFAIL tests.
7) DNS timeout tests with profile-based timeouts.
8) Latency stats (p50/p95/p99) tests:
   - deterministic percentile function; test exact outputs.
9) Reliability hints:
   - retransmission heuristic tests.
   - dup-ack tests.
10) Anomaly detectors:
   - SYN scan suspects tests.
   - NXDOMAIN client anomaly tests.
11) Integration test:
   - run full analyzer over a small packet set and compare JSON output to golden file.

QUALITY / EDGE CASE REQUIREMENTS
- Must handle empty pcaps gracefully (all zeros, severity=info).
- Must handle truncated packets best-effort (count parsing errors in errors[] but do not crash).
- Must be memory-safe for large pcaps: use streaming; avoid storing all packets.
- Time window:
  - For live capture, analysis window is capture duration.
  - For pcap, analysis window is from first packet to last packet timestamps.
- Deterministic output:
  - sort top arrays by descending count then ip string.
  - ensure map iteration order does not change JSON output (use slices sorted before output).
- Versioning:
  - tool.version is build-time settable via ldflags; default "dev".
  - schema_version is constant "1.0.0" for this initial release.

ANTICIPATED QUESTIONS & PRE-APPROVED ANSWERS
Q: Should stderr be used for errors?
A: No. Output JSON only. Put error details in `errors` array; exit non-zero.

Q: What default interface for capture?
A: Implement `--iface` optional. On Linux, default to "any". On non-Linux, choose first non-loopback interface deterministically. Document in help JSON.

Q: Do we support pcapng?
A: Yes, support both PCAP and PCAPNG via gopacket.

Q: How do we define flows_total?
A: Define as count of unique TCP 4-tuples observed (src ip, src port, dst ip, dst port) regardless of direction OR treat bidirectional as one flow by normalizing endpoints. Choose ONE approach, document it, and make tests match. Preferred: bidirectional normalization (canonical ordering) so a TCP connection counts once.

Q: How do we compute retransmissions reliably?
A: Use a heuristic: if a segment with same seq number and overlapping payload length appears again in the same direction after some time, count as retransmission. This is not perfect but acceptable for this tool; tests should reflect heuristic behavior.

Q: DNS timeout window?
A: Use thresholds profile:
  - lan: 2s
  - wan: 5s
Make configurable in code, but not required as CLI flag in v1.

Q: Percentiles implementation?
A: Implement deterministic percentile function on sorted ints:
  - p50 = value at ceil(0.50*n)-1
  - p95 = value at ceil(0.95*n)-1
  - p99 = value at ceil(0.99*n)-1
For n=0, return 0s. Test exact results.

Q: Help output needs to be detailed, but only JSON is allowed—how?
A: `--help` outputs JSON with `run.mode="help"` and populated `help` object (description, commands, flags, defaults, examples, signals).

Q: Can we add more indicators later?
A: Yes, but never remove/rename fields; only add new optional fields. Keep schema_version stable unless breaking changes (avoid).

IMPLEMENTATION CONSTRAINTS
- Do not include any external services.
- Do not require root for PCAP mode.
- For capture mode, document that elevated privileges or caps may be required; return a JSON error with code "CAPTURE_PERMISSION" on permission failure.

ACCEPTANCE CRITERIA
- `sharkclaw pcap --file test.pcap` outputs valid JSON only.
- `sharkclaw capture --duration 10s` outputs valid JSON only (or JSON error with non-zero exit if capture fails).
- `sharkclaw --help` outputs valid JSON only with detailed help content.
- Schema keys always present and stable.
- All tests pass with `go test ./...`.

Proceed with TDD, implement the above, and ensure the repo is ready for a user to build/run immediately.
