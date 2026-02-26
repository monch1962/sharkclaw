# SharkClaw

SharkClaw is a production-quality Go CLI tool that detects and counts "weird" network behaviors indicative of attacks and/or network problems.

## Features

- Analyze PCAP/PCAPNG files
- Capture live traffic with configurable duration
- Detect high-latency flows (p50, p95, p99 latency metrics)
- Monitor TCP reliability hints (retransmissions, duplicate ACKs, resets)
- Detect incomplete TCP handshakes
- Analyze DNS RTT (query-response tracking)
- Detect DNS failures (NXDOMAIN, SERVFAIL, timeouts)
- Identify top talkers (sources and destinations)
- Configurable profiles (LAN/WAN) with custom thresholds

## Installation

```bash
go build -o sharkclaw ./cmd/sharkclaw
```

## Usage

### Analyze a PCAP File

```bash
./sharkclaw pcap --file test.pcap
```

### Capture Live Traffic

```bash
./sharkclaw capture --duration 10s
```

### With Options

```bash
./sharkclaw capture --duration 30s --profile lan --filter "tcp port 80"
```

### Help

```bash
./sharkclaw --help
```

## Command Reference

### PCAP Mode

```bash
sharkclaw pcap --file <path> [--filter <bpf>] [--profile lan|wan] [--pretty] [--include-topN <n>]
```

### Capture Mode

```bash
sharkclaw capture [--duration <seconds|GoDuration>] [--iface <name>] [--filter <bpf>] [--profile lan|wan] [--pretty] [--include-topN <n>]
```

### Help

```bash
sharkclaw --help
sharkclaw -h
sharkclaw help
```

## Options

- `--file`: Path to PCAP/PCAPNG file (PCAP mode only)
- `--duration`: Capture duration (e.g., 10s, 30s, 5m). Default: "10s"
- `--iface`: Network interface for capture (Linux: "any", else explicit interface required)
- `--filter`: BPF filter for packet capture (e.g., "tcp port 80")
- `--profile`: Threshold profile (lan|wan). Default: "wan"
- `--pretty`: Output pretty-printed JSON
- `--include-topN`: Limit top talkers arrays to N entries. Default: 5

## Output Format

The tool outputs valid JSON only, no human-readable logs on stdout or stderr.

### Example Output

```json
{
  "schema_version": "1.0.0",
  "tool": {
    "name": "sharkclaw",
    "version": "dev"
  },
  "run": {
    "mode": "pcap",
    "start_time": "2026-02-26T10:00:00Z",
    "end_time": "2026-02-26T10:00:10Z",
    "duration": "10s",
    "duration_seconds": 10,
    "profile": "lan",
    "include_topN": 5
  },
  "summary": {
    "schema_version": "1.0.0",
    "signals_triggered": 0,
    "severity": "info"
  },
  "metrics": {
    "tcp_metrics": {
      "syn_total": 100,
      "incomplete_handshakes": {
        "count": 15,
        "rate_percent": 15,
        "severity": "low"
      },
      "resets": {
        "count": 3,
        "severity": "info"
      },
      "reliability_hints": {
        "retransmissions": {
          "count": 5,
          "severity": "info"
        },
        "dup_acks": {
          "count": 2,
          "severity": "info"
        }
      }
    }
  },
  "top_talkers": {
    "sources": [
      {
        "ip": "192.168.1.100",
        "new_connections": 45,
        "bytes": 154200
      }
    ],
    "destinations": [
      {
        "ip": "10.0.0.50",
        "new_connections": 30,
        "bytes": 98700
      }
    ]
  },
  "errors": []
}
```

## Signals Detected

- **Incomplete TCP Handshakes**: SYN packets without corresponding SYN-ACK and ACK
- **TCP Resets**: RST packets in a flow
- **TCP Retransmissions**: Repeated segments with same sequence number
- **Duplicate ACKs**: Repeated ACK numbers without forward progress
- **High Latency**: Elevated TCP handshake RTT or DNS RTT (p50, p95, p99)
- **DNS Failures**: NXDOMAIN, SERVFAIL, or timeouts
- **Top Talkers**: Network entities with highest connection and byte counts

## Thresholds

The tool uses two profiles with different expectations:

### LAN Profile (stricter expectations)
- Handshake RTT p50: >200ms (medium), >500ms (high), >1200ms (critical)
- DNS RTT p50: >150ms (medium), >400ms (high), >1000ms (critical)
- Incomplete handshakes: >20 AND >5% (medium), >100 OR >15% (high)
- TCP resets: >5 AND >1/1k (low), >10 AND >5/1k (medium), >50 OR >20/1k (high)
- Retransmissions: >2% (medium), >8% (high)
- DNS failures: >8 AND >2% (medium), >25 OR >10% (high) [Note: test failures remain in thresholds package]

### WAN Profile (looser expectations)
- Handshake RTT p50: >800ms (medium), >1500ms (high), >3500ms (critical)
- DNS RTT p50: >400ms (medium), >900ms (high), >2500ms (critical)
- Incomplete handshakes: >20 AND >5% (medium), >100 OR >15% (high)
- TCP resets: >5 AND >1/1k (low), >10 AND >5/1k (medium), >50 OR >20/1k (high)
- Retransmissions: >2% (medium), >8% (high)
- DNS failures: >8 AND >2% (medium), >25 OR >10% (high) [Note: test failures remain in thresholds package]

## Error Handling

The tool returns a non-zero exit code for tool errors (invalid args, file not found, parse failure, permission error, capture failure).

## Operational Notes

### Capture Mode Privileges

On Linux, capture mode requires elevated privileges or CAP_NET_RAW capability. On other systems, you must explicitly specify the network interface with `--iface`.

### File Permissions

For PCAP mode, the tool does not require any special privileges. The PCAP file can be read by any user with read access.

## Schema Versioning

The tool follows semantic versioning for its output schema. The `schema_version` field is always present and is incremented for breaking changes. The `tool.version` field is build-time settable via ldflags.

## Contributing

This tool is built with TDD methodology and includes comprehensive tests for all features.

## License

MIT
