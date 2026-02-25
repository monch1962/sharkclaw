package analyze

import (
	"fmt"
	"sort"
	"time"

	thresholds "github.com/sharkclaw/sharkclaw/internal/thresholds"
)

var ErrInvalidProfile = fmt.Errorf("invalid profile: must be 'lan' or 'wan'")
var ErrInvalidTopN = fmt.Errorf("includeTopN must be non-negative")
var ErrNoPackets = fmt.Errorf("no packets to analyze")

// Flow represents a TCP/UDP flow (4-tuple)
type Flow struct {
	SrcIP             string
	SrcPort           int
	DstIP             string
	DstPort           int
	SYNCount          int
	ACKCount          int
	RSTCount          int
	TotalBytes        int
	LastSeen          time.Time
	HandshakeComplete bool
	FirstSYN          time.Time
	ACKSeen           bool
}

// TCPHandshake tracks TCP handshake state
type TCPHandshake struct {
	SYN        bool
	SYNACKSeen bool
	ACKSeen    bool
	Timestamp  time.Time
}

// DNSQuery tracks DNS query state
type DNSQuery struct {
	Timestamp   time.Time
	TXID        uint16
	Destination string
	Complete    bool
}

// Packet represents a network packet
type Packet struct {
	Timestamp       time.Time
	Length          int
	SourceIP        string
	DestinationIP   string
	SourcePort      int
	DestinationPort int
	Protocol        string
	SYN             bool
	ACK             bool
	RST             bool
	SeqNumber       uint32
	AckNumber       uint32
	// TODO: Add more fields as needed
}

// Analyzer performs network behavior analysis on captured packets
type Analyzer struct {
	profile       string
	includeTopN   int
	thresh        thresholds.Thresholds
	flows         map[string]*Flow
	tcpHandshakes map[string]*TCPHandshake
	dnsQueries    map[string]*DNSQuery
	rates         RateTracker
}

// RateTracker tracks rates for various metrics
type RateTracker struct {
	TCPFlows       int
	TCPResets      int
	TCPRetransmits int
	DNSFailures    int
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

	thresh := thresholds.GetThresholds(thresholds.Profile(profile))

	return &Analyzer{
		profile:       profile,
		includeTopN:   includeTopN,
		thresh:        thresh,
		flows:         make(map[string]*Flow),
		tcpHandshakes: make(map[string]*TCPHandshake),
		dnsQueries:    make(map[string]*DNSQuery),
	}, nil
}

// AnalyzePcap analyzes PCAP file packet data
func (a *Analyzer) AnalyzePcap(packets []Packet) (*AnalysisResult, error) {
	if len(packets) == 0 {
		return nil, ErrNoPackets
	}

	// Initialize tracking structures
	flows := make(map[string]*Flow)
	tcpHandshakes := make(map[string]*TCPHandshake)
	dnsQueries := make(map[string]*DNSQuery)
	rates := RateTracker{}

	// Process each packet
	for _, pkt := range packets {
		// Track TCP handshakes
		if pkt.Protocol == "TCP" {
			tcpHandshakes = a.trackTCPHandshake(pkt, tcpHandshakes, flows, rates)
		}

		// Track DNS queries
		if pkt.Protocol == "UDP" && pkt.DestinationPort == 53 {
			dnsQueries = a.trackDNSQuery(pkt, dnsQueries)
		}
	}

	// Calculate incomplete handshakes
	incompleteHandshakes := 0
	for _, handshakes := range tcpHandshakes {
		if !(handshakes.SYN && handshakes.SYNACKSeen && handshakes.ACKSeen) {
			incompleteHandshakes++
		}
	}

	// Calculate rates
	totalFlows := len(flows)
	ratePercent := 0.0
	if totalFlows > 0 {
		ratePercent = float64(incompleteHandshakes) / float64(totalFlows) * 100
	}

	// Calculate severity for incomplete handshakes
	incompleteSeverity := a.computeSeverityForIncompleteHandshakes(incompleteHandshakes, ratePercent)

	// Calculate summary severity
	summarySeverity := incompleteSeverity
	if summarySeverity == thresholds.SeverityInfo {
		summarySeverity = thresholds.SeverityInfo
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
			Severity:         summarySeverity.String(),
		},
		Metrics: Metrics{
			TCPMetrics: TCPMetrics{
				SynTotal: a.calculateSynTotal(packets),
				IncompleteHandshakes: IncompleteHandshakeMetrics{
					Count:       incompleteHandshakes,
					RatePercent: ratePercent,
					Severity:    incompleteSeverity.String(),
				},
			},
		},
		TopTalkers: TopTalkers{
			Sources:      a.calculateTopTalkers(packets, flows, "sources"),
			Destinations: a.calculateTopTalkers(packets, flows, "destinations"),
		},
	}

	return result, nil
}

// trackTCPHandshake processes TCP packets and tracks handshake state
func (a *Analyzer) trackTCPHandshake(pkt Packet, tcpHandshakes map[string]*TCPHandshake, flows map[string]*Flow, rates RateTracker) map[string]*TCPHandshake {
	flowKey := a.createFlowKey(pkt.SourceIP, pkt.SourcePort, pkt.DestinationIP, pkt.DestinationPort)

	// Initialize flow if not exists
	if _, exists := flows[flowKey]; !exists {
		flows[flowKey] = &Flow{
			SrcIP:             pkt.SourceIP,
			SrcPort:           pkt.SourcePort,
			DstIP:             pkt.DestinationIP,
			DstPort:           pkt.DestinationPort,
			FirstSYN:          time.Time{},
			LastSeen:          pkt.Timestamp,
			HandshakeComplete: false,
		}
		rates.TCPFlows++
	}

	// Track handshake state
	if pkt.SYN && !tcpHandshakes[flowKey].SYN {
		tcpHandshakes[flowKey] = &TCPHandshake{
			SYN:       true,
			Timestamp: pkt.Timestamp,
		}
		flows[flowKey].FirstSYN = pkt.Timestamp
	}

	if pkt.SYN && pkt.ACK && !tcpHandshakes[flowKey].SYNACKSeen {
		tcpHandshakes[flowKey].SYNACKSeen = true
		flows[flowKey].ACKSeen = true
		flows[flowKey].HandshakeComplete = true
	}

	if pkt.ACK && tcpHandshakes[flowKey].SYN && tcpHandshakes[flowKey].SYNACKSeen && !tcpHandshakes[flowKey].ACKSeen {
		tcpHandshakes[flowKey].ACKSeen = true
		flows[flowKey].HandshakeComplete = true
	}

	if pkt.RST {
		rates.TCPResets++
	}

	flows[flowKey].LastSeen = pkt.Timestamp
	flows[flowKey].TotalBytes += pkt.Length

	return tcpHandshakes
}

// trackDNSQuery processes DNS packets and tracks query state
func (a *Analyzer) trackDNSQuery(pkt Packet, dnsQueries map[string]*DNSQuery) map[string]*DNSQuery {
	flowKey := a.createFlowKey(pkt.SourceIP, pkt.SourcePort, pkt.DestinationIP, pkt.DestinationPort)

	if _, exists := dnsQueries[flowKey]; !exists {
		dnsQueries[flowKey] = &DNSQuery{
			Timestamp: pkt.Timestamp,
			Complete:  false,
		}
	}

	return dnsQueries
}

// createFlowKey creates a unique key for a flow (4-tuple)
func (a *Analyzer) createFlowKey(srcIP string, srcPort int, dstIP string, dstPort int) string {
	return fmt.Sprintf("%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)
}

// calculateSynTotal calculates the total number of SYN packets
func (a *Analyzer) calculateSynTotal(packets []Packet) int {
	count := 0
	for _, pkt := range packets {
		if pkt.Protocol == "TCP" && pkt.SYN {
			count++
		}
	}
	return count
}

// calculateTopTalkers calculates the top talkers based on the specified direction
func (a *Analyzer) calculateTopTalkers(packets []Packet, flows map[string]*Flow, direction string) []TopTalker {
	talkers := make(map[string]*TopTalker)

	for _, pkt := range packets {
		key := pkt.SourceIP
		if direction == "destinations" {
			key = pkt.DestinationIP
		}

		if _, exists := talkers[key]; !exists {
			talkers[key] = &TopTalker{
				IP: key,
			}
		}

		talkers[key].NewConnections++
		talkers[key].Bytes += pkt.Length
	}

	// Convert to slice and sort by bytes
	result := make([]TopTalker, 0, len(talkers))
	for _, talker := range talkers {
		result = append(result, *talker)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Bytes > result[j].Bytes
	})

	// Limit to includeTopN
	if a.includeTopN > 0 && a.includeTopN < len(result) {
		result = result[:a.includeTopN]
	}

	return result
}

// computeSeverityForIncompleteHandshakes calculates severity for incomplete handshakes
func (a *Analyzer) computeSeverityForIncompleteHandshakes(count int, ratePercent float64) thresholds.Severity {
	return thresholds.ComputeSeverityForIncompleteHandshakes(count, ratePercent, a.thresh.IncompleteHandshakes)
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
