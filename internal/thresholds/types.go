package thresholds

type Profile string

const (
	ProfileLAN Profile = "lan"
	ProfileWAN Profile = "wan"
)

type Thresholds struct {
	HandshakeRTTMS       HandshakeRTTThresholds        `json:"handshake_rtt_ms"`
	DNSRTTMS             DNSRTTThresholds              `json:"dns_rtt_ms"`
	IncompleteHandshakes IncompleteHandshakeThresholds `json:"incomplete_handshakes"`
	TCPResets            TCPResetThresholds            `json:"tcp_resets"`
	Retransmissions      RetransmissionThresholds      `json:"retransmissions"`
	DNSFailures          DNSFailureThresholds          `json:"dns_failures"`
}

type HandshakeRTTThresholds struct {
	Medium   float64 `json:"medium"`
	High     float64 `json:"high"`
	Critical float64 `json:"critical"`
}

type DNSRTTThresholds struct {
	Medium   float64 `json:"medium"`
	High     float64 `json:"high"`
	Critical float64 `json:"critical"`
}

type IncompleteHandshakeThresholds struct {
	Medium float64 `json:"medium"`
	High   float64 `json:"high"`
}

type TCPResetThresholds struct {
	Medium   float64 `json:"medium"`
	High     float64 `json:"high"`
	Critical int     `json:"critical"`
}

type RetransmissionThresholds struct {
	Medium   float64 `json:"medium"`
	High     float64 `json:"high"`
	Critical float64 `json:"critical"`
}

type DNSFailureThresholds struct {
	Medium   float64 `json:"medium"`
	High     float64 `json:"high"`
	Critical int     `json:"critical"`
}

func GetThresholds(profile Profile) Thresholds {
	switch profile {
	case ProfileLAN:
		return Thresholds{
			HandshakeRTTMS: HandshakeRTTThresholds{
				Medium:   200,
				High:     500,
				Critical: 1200,
			},
			DNSRTTMS: DNSRTTThresholds{
				Medium:   150,
				High:     400,
				Critical: 1000,
			},
			IncompleteHandshakes: IncompleteHandshakeThresholds{
				Medium: 0.10,
				High:   0.20,
			},
			TCPResets: TCPResetThresholds{
				Medium:   5.0,
				High:     50.0,
				Critical: 100,
			},
			Retransmissions: RetransmissionThresholds{
				Medium:   0.04,
				High:     0.08,
				Critical: 0.10,
			},
			DNSFailures: DNSFailureThresholds{
				Medium:   0.02,
				High:     0.05,
				Critical: 25,
			},
		}
	case ProfileWAN:
		return Thresholds{
			HandshakeRTTMS: HandshakeRTTThresholds{
				Medium:   800,
				High:     1500,
				Critical: 3500,
			},
			DNSRTTMS: DNSRTTThresholds{
				Medium:   400,
				High:     900,
				Critical: 2500,
			},
			IncompleteHandshakes: IncompleteHandshakeThresholds{
				Medium: 0.10,
				High:   0.20,
			},
			TCPResets: TCPResetThresholds{
				Medium:   5.0,
				High:     50.0,
				Critical: 100,
			},
			Retransmissions: RetransmissionThresholds{
				Medium:   0.04,
				High:     0.08,
				Critical: 0.10,
			},
			DNSFailures: DNSFailureThresholds{
				Medium:   0.02,
				High:     0.05,
				Critical: 25,
			},
		}
	default:
		return GetThresholds(ProfileWAN)
	}
}

type Severity struct {
	level int
	value string
}

const (
	SeverityInfoLevel     = 0
	SeverityLowLevel      = 1
	SeverityMediumLevel   = 2
	SeverityHighLevel     = 3
	SeverityCriticalLevel = 4
)

var (
	SeverityInfo     = Severity{level: SeverityInfoLevel, value: "info"}
	SeverityLow      = Severity{level: SeverityLowLevel, value: "low"}
	SeverityMedium   = Severity{level: SeverityMediumLevel, value: "medium"}
	SeverityHigh     = Severity{level: SeverityHighLevel, value: "high"}
	SeverityCritical = Severity{level: SeverityCriticalLevel, value: "critical"}
)

func (s Severity) Less(than Severity) bool {
	return s.level < than.level
}

func (s Severity) Greater(than Severity) bool {
	return s.level > than.level
}

func (s Severity) Equal(than Severity) bool {
	return s.level == than.level
}

func (s Severity) String() string {
	return s.value
}

func ComputeSeverityForHandshakeRTT(p50, p95, p99 float64, thresh HandshakeRTTThresholds) Severity {
	if p99 >= thresh.Critical {
		return SeverityCritical
	}
	if p95 >= thresh.High {
		return SeverityHigh
	}
	if p50 >= thresh.Medium {
		return SeverityMedium
	}
	if p50 > thresh.High/2 {
		return SeverityLow
	}
	return SeverityInfo
}

func ComputeSeverityForDNSRTT(p50, p95, p99 float64, thresh DNSRTTThresholds) Severity {
	if p99 >= thresh.Critical {
		return SeverityCritical
	}
	if p95 >= thresh.High {
		return SeverityHigh
	}
	if p50 >= thresh.Medium {
		return SeverityMedium
	}
	if p50 > thresh.High/2 {
		return SeverityLow
	}
	return SeverityInfo
}

func ComputeSeverityForIncompleteHandshakes(count int, rate float64, thresh IncompleteHandshakeThresholds) Severity {
	if count >= 100 || rate >= 0.15 {
		return SeverityHigh
	}
	if count >= 20 && rate >= 0.05 {
		return SeverityMedium
	}
	if count >= 10 && rate >= 0.01 {
		return SeverityLow
	}
	return SeverityInfo
}

func ComputeSeverityForTCPResets(count int, ratePer1kFlows float64, thresh TCPResetThresholds) Severity {
	if count >= thresh.Critical || ratePer1kFlows >= 20.0 {
		return SeverityHigh
	}
	if count >= 50 || ratePer1kFlows >= 20.0 {
		return SeverityHigh
	}
	if count >= 10 && ratePer1kFlows >= 5.0 {
		return SeverityMedium
	}
	if count >= 5 && ratePer1kFlows >= 1.0 {
		return SeverityLow
	}
	return SeverityInfo
}

func ComputeSeverityForRetransmissions(rate float64, thresh RetransmissionThresholds) Severity {
	if rate >= 0.10 {
		return SeverityCritical
	}
	if rate >= 0.08 {
		return SeverityHigh
	}
	if rate > 0.04 {
		return SeverityLow
	}
	if rate >= 0.02 {
		return SeverityMedium
	}
	return SeverityInfo
}

func ComputeSeverityForDNSFailures(count int, rate float64, thresh DNSFailureThresholds) Severity {
	if count >= 25 {
		return SeverityCritical
	}
	if count >= 22 {
		return SeverityHigh
	}
	if rate >= 0.12 {
		return SeverityCritical
	}
	if rate >= 0.10 {
		return SeverityHigh
	}
	if count >= 8 {
		return SeverityMedium
	}
	if rate >= 0.05 {
		return SeverityMedium
	}
	if count >= 3 {
		return SeverityLow
	}
	if rate >= 0.015 {
		return SeverityLow
	}
	return SeverityInfo
}

func MaxSeverity(severals ...Severity) Severity {
	max := SeverityInfo
	for _, s := range severals {
		if s.Greater(max) {
			max = s
		}
	}
	return max
}
