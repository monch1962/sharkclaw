package analyze

import (
	"fmt"
	"time"
)

var ErrInvalidProfile = fmt.Errorf("invalid profile: must be 'lan' or 'wan'")
var ErrInvalidTopN = fmt.Errorf("includeTopN must be non-negative")
var ErrNoPackets = fmt.Errorf("no packets to analyze")

// Analyzer performs network behavior analysis on captured packets
type Analyzer struct {
	profile     string
	includeTopN int
}

// NewAnalyzer creates a new analyzer instance
func NewAnalyzer(profile string, includeTopN int) (*Analyzer, error) {
	// Validate profile
	validProfiles := map[string]bool{
		"lan":  true,
		"wan":  true,
		"help": true,
	}
	if !validProfiles[profile] {
		return nil, ErrInvalidProfile
	}

	// Validate includeTopN
	if includeTopN < 0 {
		return nil, ErrInvalidTopN
	}

	return &Analyzer{
		profile:     profile,
		includeTopN: includeTopN,
	}, nil
}

// Packet represents a network packet
type Packet struct {
	Timestamp time.Time
	Length    int
	// TODO: Add more packet fields like source IP, destination IP, ports, protocol, etc.
}

// AnalyzePcap analyzes PCAP file packet data
func (a *Analyzer) AnalyzePcap(packets []Packet) (*AnalysisResult, error) {
	if len(packets) == 0 {
		return nil, ErrNoPackets
	}

	result := &AnalysisResult{
		SchemaVersion: "1.0.0",
		Tool: ToolInfo{
			Name:    "sharkclaw",
			Version: "dev",
		},
		Run: RunData{
			Mode:            "pcap",
			StartTime:       packets[0].Timestamp,
			EndTime:         packets[len(packets)-1].Timestamp,
			Duration:        packets[len(packets)-1].Timestamp.Sub(packets[0].Timestamp),
			DurationSeconds: float64(packets[len(packets)-1].Timestamp.Sub(packets[0].Timestamp)),
			Profile:         a.profile,
			IncludeTopN:     a.includeTopN,
		},
		Summary: AnalysisSummary{
			SchemaVersion:    "1.0.0",
			SignalsTriggered: 0,
			Severity:         "info",
		},
		Metrics: Metrics{
			TCPMetrics: TCPMetrics{
				SynTotal: 0,
				IncompleteHandshakes: IncompleteHandshakeMetrics{
					Count:       0,
					RatePercent: 0,
					Severity:    "info",
				},
			},
		},
		TopTalkers: TopTalkers{
			Sources:      []TopTalker{},
			Destinations: []TopTalker{},
		},
	}

	// TODO: Implement actual packet analysis
	// This is a placeholder for the actual implementation

	return result, nil
}

// AnalyzeCapture analyzes captured traffic data
func (a *Analyzer) AnalyzeCapture(packets []Packet, iface string, duration time.Duration) (*AnalysisResult, error) {
	if len(packets) == 0 {
		return nil, ErrNoPackets
	}

	result := &AnalysisResult{
		SchemaVersion: "1.0.0",
		Tool: ToolInfo{
			Name:    "sharkclaw",
			Version: "dev",
		},
		Run: RunData{
			Mode:            "capture",
			StartTime:       packets[0].Timestamp,
			EndTime:         packets[len(packets)-1].Timestamp,
			Duration:        duration,
			DurationSeconds: float64(duration),
			Profile:         a.profile,
			IncludeTopN:     a.includeTopN,
		},
		Summary: AnalysisSummary{
			SchemaVersion:    "1.0.0",
			SignalsTriggered: 0,
			Severity:         "info",
		},
		Metrics: Metrics{
			TCPMetrics: TCPMetrics{
				SynTotal: 0,
				IncompleteHandshakes: IncompleteHandshakeMetrics{
					Count:       0,
					RatePercent: 0,
					Severity:    "info",
				},
			},
		},
		TopTalkers: TopTalkers{
			Sources:      []TopTalker{},
			Destinations: []TopTalker{},
		},
	}

	// TODO: Implement actual packet analysis
	// This is a placeholder for the actual implementation

	return result, nil
}

// AnalysisResult contains the analysis results
type AnalysisResult struct {
	SchemaVersion string          `json:"schema_version"`
	Tool          ToolInfo        `json:"tool"`
	Run           RunData         `json:"run"`
	Summary       AnalysisSummary `json:"summary"`
	Metrics       Metrics         `json:"metrics"`
	TopTalkers    TopTalkers      `json:"top_talkers"`
	Errors        []Error         `json:"errors"`
}

// ToolInfo contains tool metadata
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// RunData contains execution data
type RunData struct {
	Mode            string        `json:"mode"`
	StartTime       time.Time     `json:"start_time"`
	EndTime         time.Time     `json:"end_time"`
	Duration        time.Duration `json:"duration"`
	DurationSeconds float64       `json:"duration_seconds"`
	Profile         string        `json:"profile"`
	IncludeTopN     int           `json:"include_topN"`
}

// AnalysisSummary contains summary of the analysis
type AnalysisSummary struct {
	SchemaVersion    string `json:"schema_version"`
	SignalsTriggered int    `json:"signals_triggered"`
	Severity         string `json:"severity"`
}

// Metrics contains network metrics
type Metrics struct {
	TCPMetrics TCPMetrics `json:"tcp_metrics"`
}

// TCPMetrics contains TCP-specific metrics
type TCPMetrics struct {
	SynTotal             int                        `json:"syn_total"`
	IncompleteHandshakes IncompleteHandshakeMetrics `json:"incomplete_handshakes"`
	Rets                 ResetMetrics               `json:"resets"`
	ReliabilityHints     ReliabilityHints           `json:"reliability_hints"`
}

// IncompleteHandshakeMetrics tracks incomplete TCP handshakes
type IncompleteHandshakeMetrics struct {
	Count       int     `json:"count"`
	RatePercent float64 `json:"rate_percent"`
	Severity    string  `json:"severity"`
}

// ResetMetrics tracks TCP resets
type ResetMetrics struct {
	Count int `json:"count"`
}

// ReliabilityHints contains TCP reliability metrics
type ReliabilityHints struct {
	Retransmissions RetransmissionMetrics `json:"retransmissions"`
	DupACKs         DuplicateACKMetrics   `json:"dup_acks"`
}

// RetransmissionMetrics tracks TCP retransmissions
type RetransmissionMetrics struct {
	Count int `json:"count"`
}

// DuplicateACKMetrics tracks duplicate ACKs
type DuplicateACKMetrics struct {
	Count int `json:"count"`
}

// TopTalkers contains top talker data
type TopTalkers struct {
	Sources      []TopTalker `json:"sources"`
	Destinations []TopTalker `json:"destinations"`
}

// TopTalker represents a network entity
type TopTalker struct {
	IP             string `json:"ip"`
	NewConnections int    `json:"new_connections"`
	Bytes          int    `json:"bytes"`
}

// Error represents an analysis error
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
