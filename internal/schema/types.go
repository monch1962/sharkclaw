package schema

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

const SchemaVersion = "1.0.0"
const ToolName = "sharkclaw"

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type RunMode string

const (
	RunModePCAP    RunMode = "pcap"
	RunModeCapture RunMode = "capture"
	RunModeHelp    RunMode = "help"
)

type TopTalker struct {
	IP             string `json:"ip"`
	NewConnections int    `json:"new_connections"`
	Bytes          int    `json:"bytes"`
}

type TopTalkers struct {
	Sources      []TopTalker `json:"sources"`
	Destinations []TopTalker `json:"destinations"`
}

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

type TCPMetrics struct {
	SynTotal             int                        `json:"syn_total"`
	IncompleteHandshakes IncompleteHandshakeMetrics `json:"incomplete_handshakes"`
	Resets               ResetMetrics               `json:"resets"`
	ReliabilityHints     ReliabilityHints           `json:"reliability_hints"`
	Latency              LatencyMetrics             `json:"latency"`
}

type IncompleteHandshakeMetrics struct {
	Count       int      `json:"count"`
	RatePercent float64  `json:"rate_percent"`
	Severity    Severity `json:"severity"`
}

type ResetMetrics struct {
	Count          int      `json:"count"`
	RatePer1kFlows float64  `json:"rate_per_1k_flows"`
	Severity       Severity `json:"severity"`
}

type ReliabilityHints struct {
	Retransmissions RetransmissionMetrics `json:"retransmissions"`
	DupACKs         DuplicateACKMetrics   `json:"dup_acks"`
	OutOfOrder      OutOfOrderMetrics     `json:"out_of_order"`
}

type RetransmissionMetrics struct {
	Count       int      `json:"count"`
	RatePercent float64  `json:"rate_percent"`
	Severity    Severity `json:"severity"`
}

type DuplicateACKMetrics struct {
	Count       int      `json:"count"`
	RatePercent float64  `json:"rate_percent"`
	Severity    Severity `json:"severity"`
}

type OutOfOrderMetrics struct {
	Count       int      `json:"count"`
	RatePercent float64  `json:"rate_percent"`
	Severity    Severity `json:"severity"`
}

type LatencyMetrics struct {
	HandshakeRTTms HandshakeRTTMetrics `json:"handshake_rtt_ms"`
}

type HandshakeRTTMetrics struct {
	P50            int      `json:"p50"`
	P95            int      `json:"p95"`
	P99            int      `json:"p99"`
	AboveThreshold int      `json:"above_threshold"`
	Severity       Severity `json:"severity"`
}

type DNSMetrics struct {
	Queries      int               `json:"queries"`
	Failures     FailureMetrics    `json:"failures"`
	NXDOMAIN     int               `json:"nxdomain"`
	SERVFAIL     int               `json:"servfail"`
	Timeouts     int               `json:"timeouts"`
	LatencyRTTms LatencyRTTMetrics `json:"latency_rtt_ms"`
}

type FailureMetrics struct {
	Count       int      `json:"count"`
	RatePercent float64  `json:"rate_percent"`
	Severity    Severity `json:"severity"`
}

type LatencyRTTMetrics struct {
	P50            int      `json:"p50"`
	P95            int      `json:"p95"`
	P99            int      `json:"p99"`
	AboveThreshold int      `json:"above_threshold"`
	Severity       Severity `json:"severity"`
}

type AnomalyMetrics struct {
	SynScanSuspects    AnomalySuspects   `json:"syn_scan_suspects"`
	DNSNxdomainClients AnomalyDNSClients `json:"dns_nxdomain_clients"`
}

type AnomalySuspects struct {
	Count int                  `json:"count"`
	Top   []AnomalySuspectItem `json:"top"`
}

type AnomalySuspectItem struct {
	IP                    string  `json:"ip"`
	Syn                   int     `json:"syn"`
	Completed             int     `json:"completed"`
	CompletionRatePercent float64 `json:"completion_rate_percent"`
}

type AnomalyDNSClients struct {
	Count int                    `json:"count"`
	Top   []AnomalyDNSClientItem `json:"top"`
}

type AnomalyDNSClientItem struct {
	IP                  string  `json:"ip"`
	Queries             int     `json:"queries"`
	NXDOMAIN            int     `json:"nxdomain"`
	NXDomainRatePercent float64 `json:"nxdomain_rate_percent"`
}

type Metrics struct {
	FlowsTotal int            `json:"flows_total"`
	TCP        TCPMetrics     `json:"tcp"`
	DNS        DNSMetrics     `json:"dns"`
	Anomalies  AnomalyMetrics `json:"anomalies"`
}

type Summary struct {
	Severity         Severity `json:"severity"`
	SignalsTriggered int      `json:"signals_triggered"`
}

type Input struct {
	PcapFile string `json:"pcap_file"`
}

type CaptureConfig struct {
	Iface string `json:"iface"`
	BPF   string `json:"bpf"`
}

type Run struct {
	Mode            RunMode       `json:"mode"`
	StartTime       time.Time     `json:"start_time"`
	EndTime         time.Time     `json:"end_time"`
	DurationSeconds float64       `json:"duration_seconds"`
	Input           Input         `json:"input"`
	Capture         CaptureConfig `json:"capture"`
	Profile         string        `json:"profile"`
}

type Help struct {
	Description string        `json:"description"`
	Commands    []CommandInfo `json:"commands"`
	Flags       []FlagInfo    `json:"flags"`
	Signals     []SignalInfo  `json:"signals"`
}

type CommandInfo struct {
	Name        string   `json:"name"`
	Examples    []string `json:"examples"`
	Description string   `json:"description"`
}

type FlagInfo struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Default     string `json:"default"`
	Description string `json:"description"`
}

type SignalInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Meaning     string `json:"meaning"`
}

type Result struct {
	SchemaVersion string     `json:"schema_version"`
	Tool          ToolInfo   `json:"tool"`
	Run           Run        `json:"run"`
	Summary       Summary    `json:"summary"`
	Metrics       Metrics    `json:"metrics"`
	TopTalkers    TopTalkers `json:"top_talkers"`
	Errors        []Error    `json:"errors"`
	Help          Help       `json:"help"`
}

type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func NewResult(mode RunMode, profile string, startTime, endTime time.Time, durationSeconds float64) Result {
	return Result{
		SchemaVersion: SchemaVersion,
		Tool: ToolInfo{
			Name:    ToolName,
			Version: "dev", // Will be set via ldflags
		},
		Run: Run{
			Mode:            mode,
			StartTime:       startTime.UTC(),
			EndTime:         endTime.UTC(),
			DurationSeconds: durationSeconds,
			Input: Input{
				PcapFile: "",
			},
			Capture: CaptureConfig{
				Iface: "",
				BPF:   "",
			},
			Profile: profile,
		},
		Summary: Summary{
			Severity:         SeverityInfo,
			SignalsTriggered: 0,
		},
		Metrics: Metrics{
			FlowsTotal: 0,
			TCP:        NewTCPMetrics(),
			DNS:        NewDNSMetrics(),
			Anomalies:  NewAnomalyMetrics(),
		},
		TopTalkers: TopTalkers{
			Sources:      make([]TopTalker, 0),
			Destinations: make([]TopTalker, 0),
		},
		Errors: []Error{},
		Help:   NewHelp(),
	}
}

func NewTCPMetrics() TCPMetrics {
	return TCPMetrics{
		SynTotal: 0,
		IncompleteHandshakes: IncompleteHandshakeMetrics{
			Count:       0,
			RatePercent: 0,
			Severity:    SeverityInfo,
		},
		Resets: ResetMetrics{
			Count:          0,
			RatePer1kFlows: 0,
			Severity:       SeverityInfo,
		},
		ReliabilityHints: ReliabilityHints{
			Retransmissions: RetransmissionMetrics{
				Count:       0,
				RatePercent: 0,
				Severity:    SeverityInfo,
			},
			DupACKs: DuplicateACKMetrics{
				Count:       0,
				RatePercent: 0,
				Severity:    SeverityInfo,
			},
			OutOfOrder: OutOfOrderMetrics{
				Count:       0,
				RatePercent: 0,
				Severity:    SeverityInfo,
			},
		},
		Latency: LatencyMetrics{
			HandshakeRTTms: HandshakeRTTMetrics{
				P50:            0,
				P95:            0,
				P99:            0,
				AboveThreshold: 0,
				Severity:       SeverityInfo,
			},
		},
	}
}

func NewDNSMetrics() DNSMetrics {
	return DNSMetrics{
		Queries: 0,
		Failures: FailureMetrics{
			Count:       0,
			RatePercent: 0,
			Severity:    SeverityInfo,
		},
		NXDOMAIN: 0,
		SERVFAIL: 0,
		Timeouts: 0,
		LatencyRTTms: LatencyRTTMetrics{
			P50:            0,
			P95:            0,
			P99:            0,
			AboveThreshold: 0,
			Severity:       SeverityInfo,
		},
	}
}

func NewAnomalyMetrics() AnomalyMetrics {
	return AnomalyMetrics{
		SynScanSuspects: AnomalySuspects{
			Count: 0,
			Top:   make([]AnomalySuspectItem, 0),
		},
		DNSNxdomainClients: AnomalyDNSClients{
			Count: 0,
			Top:   make([]AnomalyDNSClientItem, 0),
		},
	}
}

func NewHelp() Help {
	return Help{
		Description: "Detects and counts 'weird' network behaviors indicative of attacks and/or network problems.",
		Commands: []CommandInfo{
			{
				Name: "pcap",
				Examples: []string{
					"sharkclaw pcap --file test.pcap",
					"sharkclaw pcap --file test.pcap --profile wan",
					"sharkclaw pcap --file test.pcap --include-topN 10",
				},
				Description: "Analyze a PCAP or PCAPNG file",
			},
			{
				Name: "capture",
				Examples: []string{
					"sharkclaw capture --duration 10s",
					"sharkclaw capture --duration 30s --profile lan",
					"sharkclaw capture --iface eth0 --duration 15s",
				},
				Description: "Capture live traffic for a specified duration and analyze",
			},
			{
				Name: "help",
				Examples: []string{
					"sharkclaw --help",
					"sharkclaw -h",
					"sharkclaw help",
				},
				Description: "Display help information",
			},
		},
		Flags: []FlagInfo{
			{
				Name:        "--file",
				Type:        "string",
				Default:     "",
				Description: "Path to PCAP/PCAPNG file (PCAP mode only)",
			},
			{
				Name:        "--duration",
				Type:        "string (GoDuration)",
				Default:     "10s",
				Description: "Capture duration (e.g., 10s, 30s, 5m). PCAP mode: use file instead.",
			},
			{
				Name:        "--iface",
				Type:        "string",
				Default:     "any (Linux), explicit interface required otherwise",
				Description: "Network interface for capture (capture mode only)",
			},
			{
				Name:        "--filter",
				Type:        "BPF string",
				Default:     "",
				Description: "BPF filter for packet capture (e.g., 'tcp port 80')",
			},
			{
				Name:        "--profile",
				Type:        "lan|wan",
				Default:     "wan",
				Description: "Threshold profile (affects high-latency thresholds and DNS timeouts)",
			},
			{
				Name:        "--pretty",
				Type:        "boolean",
				Default:     "false",
				Description: "Output pretty-printed JSON",
			},
			{
				Name:        "--include-topN",
				Type:        "integer",
				Default:     "5",
				Description: "Limit top talkers arrays to N entries (0 disables)",
			},
		},
		Signals: []SignalInfo{
			{
				Name:        "Incomplete TCP Handshakes",
				Description: "SYN packets without corresponding SYN-ACK and ACK",
				Meaning:     "Potential connection attempts that were never completed",
			},
			{
				Name:        "TCP Resets",
				Description: "RST packets in a flow",
				Meaning:     "Forced connection termination",
			},
			{
				Name:        "TCP Retransmissions",
				Description: "Repeated segments with same sequence number",
				Meaning:     "Packet loss, congestion, or network issues",
			},
			{
				Name:        "Duplicate ACKs",
				Description: "Repeated ACK numbers without forward progress",
				Meaning:     "Possible packet loss or reordering",
			},
			{
				Name:        "High Latency",
				Description: "Elevated TCP handshake RTT or DNS RTT",
				Meaning:     "Network congestion, poor connectivity",
			},
			{
				Name:        "DNS Failures",
				Description: "NXDOMAIN, SERVFAIL, or timeouts",
				Meaning:     "Domain resolution problems",
			},
			{
				Name:        "SYN Scan Suspects",
				Description: "IPs with high SYN rate and low completion",
				Meaning:     "Potential port scanners or attack attempts",
			},
			{
				Name:        "DNS NXDOMAIN Anomalies",
				Description: "High NXDOMAIN rate per client",
				Meaning:     "DNS poisoning or malicious activity",
			},
		},
	}
}

func AddError(result *Result, code, message string) {
	result.Errors = append(result.Errors, Error{
		Code:    code,
		Message: message,
	})
}

func (t *TopTalkers) AddSource(ip string, newConnections int, bytes int) {
	for i, existing := range t.Sources {
		if existing.IP == ip {
			t.Sources[i].NewConnections += newConnections
			t.Sources[i].Bytes += bytes
			return
		}
	}
	t.Sources = append(t.Sources, TopTalker{
		IP:             ip,
		NewConnections: newConnections,
		Bytes:          bytes,
	})
}

func (t *TopTalkers) AddDestination(ip string, newConnections int, bytes int) {
	for i, existing := range t.Destinations {
		if existing.IP == ip {
			t.Destinations[i].NewConnections += newConnections
			t.Destinations[i].Bytes += bytes
			return
		}
	}
	t.Destinations = append(t.Destinations, TopTalker{
		IP:             ip,
		NewConnections: newConnections,
		Bytes:          bytes,
	})
}

func (t *TopTalkers) SortAndLimit(limit int) {
	t.Sources = sortAndLimit(t.Sources, limit)
	t.Destinations = sortAndLimit(t.Destinations, limit)
}

func sortAndLimit(talkers []TopTalker, limit int) []TopTalker {
	if limit <= 0 {
		return []TopTalker{}
	}

	if len(talkers) <= limit {
		return talkers
	}

	sort.Slice(talkers, func(i, j int) bool {
		if talkers[i].NewConnections != talkers[j].NewConnections {
			return talkers[i].NewConnections > talkers[j].NewConnections
		}
		return talkers[i].IP < talkers[j].IP
	})

	return talkers[:limit]
}

func (r *Result) AddCompletionSeverity(severity Severity) {
	severityOrder := map[Severity]int{
		SeverityInfo:     1,
		SeverityLow:      2,
		SeverityMedium:   3,
		SeverityHigh:     4,
		SeverityCritical: 5,
	}

	currentOrder := severityOrder[r.Summary.Severity]
	newOrder := severityOrder[severity]

	if newOrder > currentOrder {
		r.Summary.Severity = severity
	}
}

func (r *Result) AddSignalTriggered() {
	r.Summary.SignalsTriggered++
}

func (r *Result) SetPcapFile(filePath string) {
	r.Run.Input.PcapFile = filePath
}

func (r *Result) SetCaptureInterface(iface string) {
	r.Run.Capture.Iface = iface
}

func (r *Result) SetCaptureBPF(bpf string) {
	r.Run.Capture.BPF = bpf
}

func (r *Result) SetVersion(version string) {
	r.Tool.Version = version
}

func (r *Result) AddSourceTopTalkers(limit int) {
	r.TopTalkers.SortAndLimit(limit)
}

func (r *Result) AddDestinationTopTalkers(limit int) {
	r.TopTalkers.SortAndLimit(limit)
}

func (r *Result) AddAnomalySuspect(ip string, syn int, completed int) {
	var completionRatePercent float64
	if syn > 0 {
		completionRatePercent = float64(completed) / float64(syn) * 100
	} else {
		completionRatePercent = 0
	}

	r.Metrics.Anomalies.SynScanSuspects.Top = append(r.Metrics.Anomalies.SynScanSuspects.Top, AnomalySuspectItem{
		IP:                    ip,
		Syn:                   syn,
		Completed:             completed,
		CompletionRatePercent: completionRatePercent,
	})
	r.Metrics.Anomalies.SynScanSuspects.Count++
}

func (r *Result) AddDNSNxdomainClient(ip string, queries int, nxdomain int) {
	var nxDomainRatePercent float64
	if queries > 0 {
		nxDomainRatePercent = float64(nxdomain) / float64(queries) * 100
	} else {
		nxDomainRatePercent = 0
	}

	r.Metrics.Anomalies.DNSNxdomainClients.Top = append(r.Metrics.Anomalies.DNSNxdomainClients.Top, AnomalyDNSClientItem{
		IP:                  ip,
		Queries:             queries,
		NXDOMAIN:            nxdomain,
		NXDomainRatePercent: nxDomainRatePercent,
	})
	r.Metrics.Anomalies.DNSNxdomainClients.Count++
}

func (r *Result) String() (string, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("failed to marshal result to JSON: %w", err)
	}
	return string(data), nil
}

func (r *Result) PrettyString() (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal result to JSON: %w", err)
	}
	return string(data), nil
}

func NormalizeFlowKey(srcIP string, srcPort int, dstIP string, dstPort int) string {
	if srcIP < dstIP || (srcIP == dstIP && srcPort < dstPort) {
		return fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)
	}
	return fmt.Sprintf("%s:%d-%s:%d", dstIP, dstPort, srcIP, srcPort)
}

func GetPercentile(sortedValues []int, percentile float64) int {
	if len(sortedValues) == 0 {
		return 0
	}

	index := int(float64(len(sortedValues)-1) * percentile)
	if index < 0 {
		index = 0
	}
	if index >= len(sortedValues) {
		index = len(sortedValues) - 1
	}

	return sortedValues[index]
}
