# SharkClaw

SharkClaw is a production-quality Go CLI tool that detects and counts "weird" network behaviors indicative of attacks and/or network problems.

## Features

- Analyze PCAP/PCAPNG files
- Capture live traffic with configurable duration
- Detect high-latency flows
- Monitor TCP reliability hints (retransmissions, duplicate ACKs, resets)
- Detect incomplete TCP handshakes
- Analyze DNS failures (NXDOMAIN, SERVFAIL, timeouts)
- Identify SYN scan suspects
- Detect DNS NXDOMAIN anomalies

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
    "version": "1.0.0"
  },
  "run": {
    "mode": "pcap",
    "start_time": "2026-02-24T21:09:28.185110282Z",
    "end_time": "2026-02-24T21:09:28.185110282Z",
    "duration_seconds": 10,
    "input": {
      "pcap_file": "test.pcap"
    },
    "capture": {
      "iface": "",
      "bpf": ""
    },
    "profile": "wan"
  },
  "summary": {
    "severity": "info",
    "signals_triggered": 0
  },
  "metrics": {
    "flows_total": 0,
    "tcp": {
      "syn_total": 0,
      "incomplete_handshakes": {
        "count": 0,
        "rate_percent": 0,
        "severity": "info"
      },
      "resets": {
        "count": 0,
        "rate_per_1k_flows": 0,
        "severity": "info"
      },
      "reliability_hints": {
        "retransmissions": {
          "count": 0,
          "rate_percent": 0,
          "severity": "info"
        },
        "dup_acks": {
          "count": 0,
          "rate_percent": 0,
          "severity": "info"
        },
        "out_of_order": {
          "count": 0,
          "rate_percent": 0,
          "severity": "info"
        }
      },
      "latency": {
        "handshake_rtt_ms": {
          "p50": 0,
          "p95": 0,
          "p99": 0,
          "above_threshold": 0,
          "severity": "info"
        }
      }
    },
    "dns": {
      "queries": 0,
      "failures": {
        "count": 0,
        "rate_percent": 0,
        "severity": "info"
      },
      "nxdomain": 0,
      "servfail": 0,
      "timeouts": 0,
      "latency_rtt_ms": {
        "p50": 0,
        "p95": 0,
        "p99": 0,
        "above_threshold": 0,
        "severity": "info"
      }
    },
    "anomalies": {
      "syn_scan_suspects": {
        "count": 0,
        "top": []
      },
      "dns_nxdomain_clients": {
        "count": 0,
        "top": []
      }
    }
  },
  "top_talkers": {
    "sources": [],
    "destinations": []
  },
  "errors": [],
  "help": {
    "description": "Detects and counts 'weird' network behaviors indicative of attacks and/or network problems.",
    "commands": [...],
    "flags": [...],
    "signals": [...]
  }
}
```

## Signals Detected

- **Incomplete TCP Handshakes**: SYN packets without corresponding SYN-ACK and ACK
- **TCP Resets**: RST packets in a flow
- **TCP Retransmissions**: Repeated segments with same sequence number
- **Duplicate ACKs**: Repeated ACK numbers without forward progress
- **High Latency**: Elevated TCP handshake RTT or DNS RTT
- **DNS Failures**: NXDOMAIN, SERVFAIL, or timeouts
- **SYN Scan Suspects**: IPs with high SYN rate and low completion rate
- **DNS NXDOMAIN Anomalies**: High NXDOMAIN rate per client

## Thresholds

The tool uses two profiles:

### LAN Profile (stricter expectations)
- Handshake RTT p95: >200ms (medium), >500ms (high), >1200ms (critical)
- DNS RTT p95: >150ms (medium), >400ms (high), >1000ms (critical)
- Incomplete handshakes: >20 AND >5% (medium), >100 OR >15% (high)
- TCP resets: >10 AND >5/1k (medium), >50 OR >20/1k (high)
- Retransmissions: >2% (medium), >8% (high)
- DNS failures: >5 AND >2% (medium), >20 OR >10% (high)

### WAN Profile (looser expectations)
- Handshake RTT p95: >800ms (medium), >1500ms (high), >3000ms (critical)
- DNS RTT p95: >400ms (medium), >900ms (high), >2000ms (critical)
- Incomplete handshakes: >20 AND >5% (medium), >100 OR >15% (high)
- TCP resets: >10 AND >5/1k (medium), >50 OR >20/1k (high)
- Retransmissions: >2% (medium), >8% (high)
- DNS failures: >5 AND >2% (medium), >20 OR >10% (high)

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
