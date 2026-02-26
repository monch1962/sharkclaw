# AGENTS.md

## Build, Test, and Lint Commands

### Testing

**Run all tests:**
```bash
go test ./...
```

**Run tests with verbose output:**
```bash
go test -v ./...
```

**Run tests for a single package:**
```bash
go test -v ./internal/analyze
go test -v ./internal/capture
go test -v ./internal/pcap
go test -v ./internal/schema
go test -v ./internal/thresholds
go test -v ./internal/output
go test -v ./cmd/sharkclaw
```

**Run a single test function:**
```bash
go test -v ./internal/thresholds -run TestComputeSeverityForRetransmissions
go test -v ./internal/thresholds -run TestComputeSeverityForDNSFailures
```

**Run tests with coverage:**
```bash
go test -v -cover ./...
```

**Run tests with race detector:**
```bash
go test -race ./...
```

### Building

**Build the binary:**
```bash
go build -o sharkclaw ./cmd/sharkclaw
```

**Build with race detector:**
```bash
go build -race -o sharkclaw ./cmd/sharkclaw
```

**Build with all optimizations:**
```bash
go build -ldflags="-s -w" -o sharkclaw ./cmd/sharkclaw
```

### Code Quality

**Check code format:**
```bash
go fmt ./...
```

**Check for common issues:**
```bash
go vet ./...
```

**Run linters (if configured):**
```bash
golangci-lint run ./...
```

## Code Style Guidelines

### Import Organization

**Import groups in order:**
1. Standard library (`fmt`, `os`, `time`, etc.)
2. External packages with aliases (`cli "github.com/sharkclaw/sharkclaw/internal/cli"`)
3. No grouping needed for this project size

**Example:**
```go
import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	cli "github.com/sharkclaw/sharkclaw/internal/cli"
	schema "github.com/sharkclaw/sharkclaw/internal/schema"
)
```

### File Naming

- Use camelCase for files: `analyzer.go`, `command.go`, `types.go`
- Package files with same concept go in same directory
- Test files: `*_test.go` (e.g., `types_test.go`, `types_test.go`)

### Type Naming

- Exported types start with uppercase: `Analyzer`, `Packet`, `Command`
- Unexported types use lowercase: `severity`, `thresholds`

**Example:**
```go
type Analyzer struct { ... }        // Exported
type command struct { ... }        // Unexported
```

### Function/Method Naming

- Exported functions start with uppercase: `NewAnalyzer`, `AnalyzePcap`, `Encode`
- Unexported functions use lowercase: `computeSeverity`, `parseFlags`
- Constructors use `New` prefix

**Example:**
```go
func NewAnalyzer(profile string, includeTopN int) (*Analyzer, error) {
    // ...
}

func (a *Analyzer) AnalyzePcap(packets []Packet) (*AnalysisResult, error) {
    // ...
}
```

### Error Handling

**Use `fmt.Errorf` with `%w` for wrapping errors:**
```go
return nil, fmt.Errorf("failed to parse flags: %w", err)
```

**Create named errors for validation failures:**
```go
var ErrInvalidProfile = fmt.Errorf("invalid profile: must be 'lan' or 'wan'")
var ErrInvalidTopN = fmt.Errorf("includeTopN must be non-negative")
```

**Return error from constructors on validation failure:**
```go
func NewAnalyzer(profile string, includeTopN int) (*Analyzer, error) {
    if !validProfiles[profile] {
        return nil, ErrInvalidProfile
    }
    if includeTopN < 0 {
        return nil, ErrInvalidTopN
    }
    return &Analyzer{...}, nil
}
```

### Struct Layout

- **Order:**
  1. Constants (uppercase)
  2. Type definitions
  3. Exported fields (uppercase)
  4. Unexported fields (lowercase)
  5. Exported methods
  6. Unexported methods

**Example:**
```go
type Analyzer struct {
    profile     string
    includeTopN int
}

func (a *Analyzer) AnalyzePcap(packets []Packet) (*AnalysisResult, error) {
    // ...
}
```

### Comment Style

**Doc comments for exported types and functions:**
```go
// Analyzer performs network behavior analysis on captured packets
type Analyzer struct {
    // ...
}

// AnalyzePcap analyzes PCAP file packet data
func (a *Analyzer) AnalyzePcap(packets []Packet) (*AnalysisResult, error) {
    // ...
}
```

**Use `// TODO:` for incomplete features:**
```go
// TODO: Add more packet fields like source IP, destination IP, ports, protocol, etc.
```

### JSON Serialization

- Use struct tags for JSON fields: `` `json:"field_name"``
- Include all required fields in schema
- Follow camelCase in Go, use snake_case in JSON tags

**Example:**
```go
type TCPMetrics struct {
    SynTotal       int                      `json:"syn_total"`
    IncompleteHandshakes IncompleteHandshakeMetrics `json:"incomplete_handshakes"`
}

type Command struct {
    PcapFile   string `json:"pcap_file"`
    Interface  string `json:"interface"`
    BPF        string `json:"bpf"`
}
```

### Testing

- Write tests FIRST for every feature (TDD)
- Use table-driven tests for parameterized tests
- Include multiple severity levels and edge cases
- Always use descriptive test names

**Example:**
```go
func TestComputeSeverityForRetransmissions(t *testing.T) {
    tests := []struct {
        name     string
        rate     float64
        thresh   RetransmissionThresholds
        expected Severity
    }{
        {
            name:     "Critical severity",
            rate:     0.10,
            thresh:   RetransmissionThresholds{Medium: 0.02, High: 0.08, Critical: 0.10},
            expected: SeverityCritical,
        },
        {
            name:     "High severity",
            rate:     0.06,
            thresh:   RetransmissionThresholds{Medium: 0.02, High: 0.08, Critical: 0.10},
            expected: SeverityHigh,
        },
        // ... more test cases
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := ComputeSeverityForRetransmissions(tt.rate, tt.thresh)
            if result != tt.expected {
                t.Errorf("Expected %v, got %v", tt.expected, result)
            }
        })
    }
}
```

### Validation

- Validate inputs at function entry points
- Return clear error messages for validation failures
- Validate profiles against known allowed values

**Example:**
```go
func NewAnalyzer(profile string, includeTopN int) (*Analyzer, error) {
    validProfiles := map[string]bool{
        "lan":  true,
        "wan":  true,
        "help": true,
    }
    if !validProfiles[profile] {
        return nil, ErrInvalidProfile
    }

    if includeTopN < 0 {
        return nil, ErrInvalidTopN
    }

    return &Analyzer{
        profile:     profile,
        includeTopN: includeTopN,
    }, nil
}
```

### Documentation

**For AI agents:**
- Maintain stable JSON schema - never remove or rename keys
- Include all top-level objects with default/zero values
- All output must be valid JSON only
- Exit code 0 for successful runs regardless of findings severity
- Exit code non-zero only for tool errors (invalid args, file not found, etc.)

**For other developers:**
- All exported types and functions must have doc comments
- Complex logic should be explained in comments
- Use TODO comments for incomplete features
- Update README.md when adding new features or changing behavior
