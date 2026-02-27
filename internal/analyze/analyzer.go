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
	SeqNumber         uint32
	LastACKNumber     uint32
	PreviousACKNumber uint32
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
	RTT         int64
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
	handshakeRTT  []int64 // Store handshake RTT in milliseconds
	dnsRTT        []int64 // Store DNS RTT in milliseconds
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

	totalPackets := len(packets)

	// Calculate TCP reliability metrics
	retransmissions := 0
	duplicateACKs := 0

	// Process each packet
	for _, pkt := range packets {
		// Track TCP handshakes
		if pkt.Protocol == "TCP" {
			a.trackTCPHandshake(pkt, a.tcpHandshakes, a.flows, a.rates, &retransmissions, &duplicateACKs)
		}

		// Track DNS queries
		if pkt.Protocol == "UDP" && pkt.DestinationPort == 53 {
			a.trackDNSQuery(pkt, a.dnsQueries, &a.dnsRTT)
		}
	}

	// Calculate incomplete handshakes
	incompleteHandshakes := 0
	for _, handshakes := range a.tcpHandshakes {
		if !(handshakes.SYN && handshakes.SYNACKSeen && handshakes.ACKSeen) {
			incompleteHandshakes++
		}
	}

	// Calculate rates
	totalFlows := len(a.flows)
	ratePercent := 0.0
	if totalFlows > 0 {
		ratePercent = float64(incompleteHandshakes) / float64(totalFlows) * 100
	}

	// Calculate severity for incomplete handshakes
	incompleteSeverity := a.computeSeverityForIncompleteHandshakes(incompleteHandshakes, ratePercent)

	// Calculate summary severity
	summarySeverity := incompleteSeverity

	// Calculate severity for other metrics
	resetCount := a.calculateTCPResets(packets)
	resetRate := 0.0
	if totalFlows > 0 {
		resetRate = float64(resetCount) / float64(totalFlows) * 1000 // per 1k flows
	}
	resetSeverity := a.computeSeverityForTCPResets(resetCount, resetRate)

	// Calculate retransmission rate
	retransmissionRate := 0.0
	if totalPackets > 0 {
		retransmissionRate = float64(retransmissions) / float64(totalPackets) * 100
	}
	retransmissionSeverity := a.computeSeverityForRetransmissions(retransmissionRate)

	// Calculate duplicate ACK rate
	duplicateACKRate := 0.0
	if totalPackets > 0 {
		duplicateACKRate = float64(duplicateACKs) / float64(totalPackets) * 100
	}
	duplicateACKSeverity := a.computeSeverityForDuplicateACKs(duplicateACKs, duplicateACKRate)

	// Calculate DNS failure rate
	dnsFailureRate := 0.0
	if totalPackets > 0 {
		dnsFailureRate = float64(a.rates.DNSFailures) / float64(totalPackets) * 100
	}
	dnsFailureSeverity := a.computeSeverityForDNSFailures(a.rates.DNSFailures, dnsFailureRate)

	// Calculate summary severity from all metrics
	summarySeverity = a.computeSummarySeverity(incompleteSeverity, resetSeverity, retransmissionSeverity, duplicateACKSeverity, dnsFailureSeverity, thresholds.SeverityInfo, thresholds.SeverityInfo)

	if summarySeverity == thresholds.SeverityInfo {
		summarySeverity = thresholds.SeverityInfo
	}

	// Calculate top talkers
	sources := a.calculateTopTalkers(packets, a.flows, "sources")
	destinations := a.calculateTopTalkers(packets, a.flows, "destinations")

	result := &AnalysisResult{
		Run: RunData{
			Mode:            "pcap",
			StartTime:       packets[0].Timestamp,
			EndTime:         packets[len(packets)-1].Timestamp,
			DurationSeconds: float64(packets[len(packets)-1].Timestamp.Sub(packets[0].Timestamp)),
			Profile:         a.profile,
			IncludeTopN:     a.includeTopN,
			TotalPackets:    totalPackets,
		},
		Metrics: Metrics{
			TCPMetrics: TCPMetrics{
				SynTotal: a.calculateSynTotal(packets),
				IncompleteHandshakes: IncompleteHandshakeMetrics{
					Count:       incompleteHandshakes,
					RatePercent: ratePercent,
					Severity:    incompleteSeverity.String(),
				},
				Resets: ResetMetrics{
					Count: a.calculateTCPResets(packets),
				},
				ReliabilityHints: ReliabilityHints{
					Retransmissions: RetransmissionMetrics{
						Count: retransmissions,
					},
					DupACKs: DuplicateACKMetrics{
						Count: duplicateACKs,
					},
				},
			},
		},
		Summary: Summary{
			Severity: summarySeverity.String(),
			SignalsTriggered: 0,
		},
		TopTalkers: TopTalkers{
			Sources:      sources,
			Destinations: destinations,
		},
	}

	return result, nil
}

// trackTCPHandshake processes TCP packets and tracks handshake state
func (a *Analyzer) trackTCPHandshake(pkt Packet, tcpHandshakes map[string]*TCPHandshake, flows map[string]*Flow, rates RateTracker, retransmissions *int, duplicateACKs *int) map[string]*TCPHandshake {
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
			SeqNumber:         pkt.SeqNumber,
		}
		rates.TCPFlows++
	}

	// Track handshake state
	if tcpHandshake, exists := tcpHandshakes[flowKey]; exists {
		if pkt.SYN && !tcpHandshake.SYN {
			tcpHandshakes[flowKey] = &TCPHandshake{
				SYN:       true,
				Timestamp: pkt.Timestamp,
			}
			flows[flowKey].FirstSYN = pkt.Timestamp
		}

		if pkt.SYN && pkt.ACK && !tcpHandshake.SYNACKSeen {
			// Calculate handshake RTT
			handshakeRTT := pkt.Timestamp.Sub(flows[flowKey].FirstSYN).Milliseconds()
			a.handshakeRTT = append(a.handshakeRTT, handshakeRTT)

			tcpHandshakes[flowKey].SYNACKSeen = true
			flows[flowKey].ACKSeen = true
			flows[flowKey].HandshakeComplete = true
		}

		if pkt.ACK && tcpHandshake.SYN && tcpHandshake.SYNACKSeen && !tcpHandshake.ACKSeen {
			tcpHandshakes[flowKey].ACKSeen = true
			flows[flowKey].HandshakeComplete = true
		}
	}

	// Detect retransmissions (same sequence number as previous packet)
	if pkt.SeqNumber == flows[flowKey].SeqNumber && pkt.SeqNumber != flows[flowKey].LastACKNumber {
		*retransmissions++
	}

	// Detect duplicate ACKs (ACK number doesn't advance)
	if pkt.ACK && flows[flowKey].LastACKNumber > 0 && pkt.AckNumber == flows[flowKey].LastACKNumber && flows[flowKey].LastACKNumber != flows[flowKey].PreviousACKNumber {
		*duplicateACKs++
	}

	flows[flowKey].PreviousACKNumber = flows[flowKey].LastACKNumber
	flows[flowKey].LastACKNumber = pkt.AckNumber
	flows[flowKey].SeqNumber = pkt.SeqNumber

	if pkt.RST {
		rates.TCPResets++
	}

	flows[flowKey].LastSeen = pkt.Timestamp
	flows[flowKey].TotalBytes += pkt.Length

	return tcpHandshakes
}

// trackDNSQuery processes DNS packets and tracks query state
func (a *Analyzer) trackDNSQuery(pkt Packet, dnsQueries map[string]*DNSQuery, dnsRTT *[]int64) {
	flowKey := a.createFlowKey(pkt.SourceIP, pkt.SourcePort, pkt.DestinationIP, pkt.DestinationPort)

	if _, exists := dnsQueries[flowKey]; !exists {
		dnsQueries[flowKey] = &DNSQuery{
			Timestamp: pkt.Timestamp,
			Complete:  false,
		}
	}

	// Check if this is a DNS response (typically has response flag set, or we assume if it's the next packet in sequence)
	// For simplicity, we'll mark all non-query packets as responses
	if !pkt.ACK && !pkt.SYN {
		// This is a response packet
		if dnsQueries[flowKey].Complete {
			// Calculate RTT if query was received
			if pkt.Timestamp.After(dnsQueries[flowKey].Timestamp) {
				rtt := pkt.Timestamp.Sub(dnsQueries[flowKey].Timestamp).Milliseconds()
				if rtt > 0 {
					*dnsRTT = append(*dnsRTT, rtt)
				}
				dnsQueries[flowKey].Complete = true
			}
		}
	}
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

// computeSeverityForTCPResets calculates severity for TCP resets
func (a *Analyzer) computeSeverityForTCPResets(count int, ratePer1kFlows float64) thresholds.Severity {
	return thresholds.ComputeSeverityForTCPResets(count, ratePer1kFlows, a.thresh.TCPResets)
}

// computeSeverityForRetransmissions calculates severity for retransmissions
func (a *Analyzer) computeSeverityForRetransmissions(rate float64) thresholds.Severity {
	return thresholds.ComputeSeverityForRetransmissions(rate, a.thresh.Retransmissions)
}

// computeSeverityForDuplicateACKs calculates severity for duplicate ACKs
func (a *Analyzer) computeSeverityForDuplicateACKs(count int, ratePercent float64) thresholds.Severity {
	// Duplicate ACK severity is similar to retransmission severity
	if ratePercent >= 10.0 {
		return thresholds.SeverityCritical
	}
	if ratePercent >= 5.0 {
		return thresholds.SeverityHigh
	}
	if ratePercent >= 2.0 {
		return thresholds.SeverityMedium
	}
	if ratePercent >= 1.0 {
		return thresholds.SeverityLow
	}
	return thresholds.SeverityInfo
}

// computeSeverityForDNSFailures calculates severity for DNS failures
func (a *Analyzer) computeSeverityForDNSFailures(count int, rate float64) thresholds.Severity {
	return thresholds.ComputeSeverityForDNSFailures(count, rate, a.thresh.DNSFailures)
}

// computeSeverityForHandshakeRTT calculates severity for handshake RTT
func (a *Analyzer) computeSeverityForHandshakeRTT(sortedRTT []int64) thresholds.Severity {
	if len(sortedRTT) == 0 {
		return thresholds.SeverityInfo
	}
	p50 := float64(sortedRTT[len(sortedRTT)*50/100])
	p95 := float64(sortedRTT[len(sortedRTT)*95/100])
	p99 := float64(sortedRTT[len(sortedRTT)*99/100])
	return thresholds.ComputeSeverityForHandshakeRTT(p50, p95, p99, a.thresh.HandshakeRTTMS)
}

// computeSeverityForDNSRTT calculates severity for DNS RTT
func (a *Analyzer) computeSeverityForDNSRTT(sortedRTT []int64) thresholds.Severity {
	if len(sortedRTT) == 0 {
		return thresholds.SeverityInfo
	}
	p50 := float64(sortedRTT[len(sortedRTT)*50/100])
	p95 := float64(sortedRTT[len(sortedRTT)*95/100])
	p99 := float64(sortedRTT[len(sortedRTT)*99/100])
	return thresholds.ComputeSeverityForDNSRTT(p50, p95, p99, a.thresh.DNSRTTMS)
}

// calculateLatency calculates latency statistics (p50, p95, p99)

// computeSummarySeverity calculates the overall severity summary based on all metric severities
func (a *Analyzer) computeSummarySeverity(incompleteSeverity, resetSeverity, retransmissionSeverity, duplicateACKSeverity, dnsFailureSeverity, handshakeRTTSeverity, dnsRTTSeverity thresholds.Severity) thresholds.Severity {
	maxSeverity := incompleteSeverity
	if resetSeverity.Greater(maxSeverity) {
		maxSeverity = resetSeverity
	}
	if retransmissionSeverity.Greater(maxSeverity) {
		maxSeverity = retransmissionSeverity
	}
	if duplicateACKSeverity.Greater(maxSeverity) {
		maxSeverity = duplicateACKSeverity
	}
	if dnsFailureSeverity.Greater(maxSeverity) {
		maxSeverity = dnsFailureSeverity
	}
	if handshakeRTTSeverity.Greater(maxSeverity) {
		maxSeverity = handshakeRTTSeverity
	}
	if dnsRTTSeverity.Greater(maxSeverity) {
		maxSeverity = dnsRTTSeverity
	}
	return maxSeverity
}
func (a *Analyzer) calculateLatency(latencies []int64) LatencyMetrics {
	if len(latencies) == 0 {
		return LatencyMetrics{
			P50: 0,
			P95: 0,
			P99: 0,
		}
	}

	// Sort latencies
	sorted := make([]int64, len(latencies))
	copy(sorted, latencies)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})

	p50 := int(percentile(sorted, 50))
	p95 := int(percentile(sorted, 95))
	p99 := int(percentile(sorted, 99))

	return LatencyMetrics{
		P50: p50,
		P95: p95,
		P99: p99,
	}
}

// calculateTCPResets calculates the total number of TCP RST packets
func (a *Analyzer) calculateTCPResets(packets []Packet) int {
	count := 0
	for _, pkt := range packets {
		if pkt.Protocol == "TCP" && pkt.RST {
			count++
		}
	}
	return count
}

// LatencyMetrics contains latency statistics
type LatencyMetrics struct {
	P50 int `json:"p50"`
	P95 int `json:"p95"`
	P99 int `json:"p99"`
}

// percentile calculates the nth percentile (n = 50, 95, 99)
func percentile(sorted []int64, n int) int64 {
	if len(sorted) == 0 {
		return 0
	}
	index := (len(sorted) * n) / 100
	return sorted[index]
}

// AnalyzeCapture analyzes captured traffic data
func (a *Analyzer) AnalyzeCapture(packets []Packet, iface string, duration time.Duration) (*AnalysisResult, error) {
	if len(packets) == 0 {
		return nil, ErrNoPackets
	}

	// Use the same analysis logic as AnalyzePcap
	return a.AnalyzePcap(packets)
}

// AnalysisResult contains the analysis results

// Summary contains the overall severity summary
type Summary struct {
	Severity         string `json:"severity"`
	SignalsTriggered int    `json:"signals_triggered"`
}

type AnalysisResult struct {
	Run        RunData    `json:"run"`
	Metrics    Metrics    `json:"metrics"`
	TopTalkers TopTalkers `json:"top_talkers"`
	Summary    Summary    `json:"summary"`

	Errors     []Error    `json:"errors"`
}

// RunData contains execution data
type RunData struct {
	Mode            string        `json:"mode"`
	StartTime       time.Time     `json:"start_time"`
	EndTime         time.Time     `json:"end_time"`
	Duration        time.Duration `json:"-"`
	DurationSeconds float64       `json:"duration_seconds"`
	Profile         string        `json:"profile"`
	IncludeTopN     int           `json:"include_topN"`
	TotalPackets    int           `json:"total_packets"`
}

// AnalysisSummary contains summary of the analysis

// Metrics contains network metrics
type Metrics struct {
	TCPMetrics TCPMetrics `json:"tcp_metrics"`
	DNSMetrics DNSMetrics `json:"dns_metrics"`
}

// TCPMetrics contains TCP-specific metrics
type TCPMetrics struct {
	SynTotal             int                        `json:"syn_total"`
	IncompleteHandshakes IncompleteHandshakeMetrics `json:"incomplete_handshakes"`
	Resets               ResetMetrics               `json:"resets"`
	ReliabilityHints     ReliabilityHints           `json:"reliability_hints"`
	Latency              LatencyMetrics             `json:"latency"`
}

// IncompleteHandshakeMetrics tracks incomplete TCP handshakes
type IncompleteHandshakeMetrics struct {
	Count       int     `json:"count"`
	RatePercent float64 `json:"rate_percent"`
	Severity    string  `json:"severity"`
}

// ResetMetrics tracks TCP resets
type ResetMetrics struct {
	Count       int     `json:"count"`
	RatePercent float64 `json:"rate_percent"`
	Severity    string  `json:"severity"`
}

// RetransmissionMetrics tracks TCP retransmissions
type RetransmissionMetrics struct {
	Count       int     `json:"count"`
	RatePercent float64 `json:"rate_percent"`
	Severity    string  `json:"severity"`
}

// DuplicateACKMetrics tracks duplicate ACKs
type DuplicateACKMetrics struct {
	Count       int     `json:"count"`
	RatePercent float64 `json:"rate_percent"`
	Severity    string  `json:"severity"`
}

// ReliabilityHints contains TCP reliability metrics
type ReliabilityHints struct {
	Retransmissions RetransmissionMetrics `json:"retransmissions"`
	DupACKs         DuplicateACKMetrics   `json:"dup_acks"`
}

// DNSMetrics contains DNS-specific metrics
type DNSMetrics struct {
	Queries      int               `json:"queries"`
	Failures     FailureMetrics    `json:"failures"`
	LatencyRTTms LatencyRTTMetrics `json:"latency_rtt_ms"`
}

// FailureMetrics contains DNS failure metrics
type FailureMetrics struct {
	Count       int     `json:"count"`
	RatePercent float64 `json:"rate_percent"`
	Severity    string  `json:"severity"`
}

// LatencyRTTMetrics contains DNS RTT statistics
type LatencyRTTMetrics struct {
	P50            int    `json:"p50"`
	P95            int    `json:"p95"`
	P99            int    `json:"p99"`
	AboveThreshold int    `json:"above_threshold"`
	Severity       string `json:"severity"`
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

// TopTalkers contains top talker data
type TopTalkers struct {
	Sources      []TopTalker `json:"sources"`
	Destinations []TopTalker `json:"destinations"`
}
