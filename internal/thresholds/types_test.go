package thresholds

import (
	"testing"
)

func TestGetThresholds(t *testing.T) {
	tests := []struct {
		name    string
		profile Profile
		wantLAN bool
		wantWAN bool
	}{
		{
			name:    "LAN profile",
			profile: ProfileLAN,
			wantLAN: true,
			wantWAN: false,
		},
		{
			name:    "WAN profile",
			profile: ProfileWAN,
			wantLAN: false,
			wantWAN: true,
		},
		{
			name:    "wan profile",
			profile: ProfileWAN,
			wantLAN: false,
			wantWAN: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			thresh := GetThresholds(tt.profile)

			if tt.wantLAN {
				if thresh.HandshakeRTTMS.Medium != 200 ||
					thresh.HandshakeRTTMS.High != 500 ||
					thresh.DNSRTTMS.Medium != 150 ||
					thresh.DNSRTTMS.High != 400 {
					t.Errorf("LAN thresholds mismatch")
				}
			}

			if tt.wantWAN {
				if thresh.HandshakeRTTMS.Medium != 800 ||
					thresh.HandshakeRTTMS.High != 1500 ||
					thresh.DNSRTTMS.Medium != 400 ||
					thresh.DNSRTTMS.High != 900 {
					t.Errorf("WAN thresholds mismatch")
				}
			}
		})
	}
}

func TestComputeSeverityForHandshakeRTT(t *testing.T) {
	tests := []struct {
		name     string
		p50      float64
		p95      float64
		p99      float64
		thresh   HandshakeRTTThresholds
		expected Severity
	}{
		{
			name:     "Critical severity",
			p50:      150,
			p95:      500,
			p99:      1200,
			thresh:   HandshakeRTTThresholds{Medium: 200, High: 500, Critical: 1200},
			expected: SeverityCritical,
		},
		{
			name:     "High severity",
			p50:      300,
			p95:      500,
			p99:      1000,
			thresh:   HandshakeRTTThresholds{Medium: 200, High: 500, Critical: 1200},
			expected: SeverityHigh,
		},
		{
			name:     "Medium severity",
			p50:      200,
			p95:      400,
			p99:      600,
			thresh:   HandshakeRTTThresholds{Medium: 200, High: 500, Critical: 1200},
			expected: SeverityMedium,
		},
		{
			name:     "Low severity with p50 above medium 1",
			p50:      220,
			p95:      450,
			p99:      600,
			thresh:   HandshakeRTTThresholds{Medium: 200, High: 500, Critical: 1200},
			expected: SeverityMedium,
		},
		{
			name:     "Low severity with p50 above medium 2",
			p50:      300,
			p95:      450,
			p99:      600,
			thresh:   HandshakeRTTThresholds{Medium: 200, High: 500, Critical: 1200},
			expected: SeverityMedium,
		},
		{
			name:     "Low severity with p50 above medium 1",
			p50:      220,
			p95:      450,
			p99:      600,
			thresh:   HandshakeRTTThresholds{Medium: 200, High: 500, Critical: 1200},
			expected: SeverityMedium,
		},
		{
			name:     "Low severity with p50 above medium 2",
			p50:      300,
			p95:      450,
			p99:      600,
			thresh:   HandshakeRTTThresholds{Medium: 200, High: 500, Critical: 1200},
			expected: SeverityMedium,
		},
		{
			name:     "Low severity with p50 above medium 1",
			p50:      220,
			p95:      450,
			p99:      600,
			thresh:   HandshakeRTTThresholds{Medium: 200, High: 500, Critical: 1200},
			expected: SeverityMedium,
		},
		{
			name:     "Low severity with p50 above medium 2",
			p50:      220,
			p95:      450,
			p99:      600,
			thresh:   HandshakeRTTThresholds{Medium: 200, High: 500, Critical: 1200},
			expected: SeverityMedium,
		},
		{
			name:     "Low severity with p50 above medium 3",
			p50:      300,
			p95:      450,
			p99:      600,
			thresh:   HandshakeRTTThresholds{Medium: 200, High: 500, Critical: 1200},
			expected: SeverityMedium,
		},
		{
			name:     "Low severity with p50 above medium 2",
			p50:      300,
			p95:      450,
			p99:      600,
			thresh:   HandshakeRTTThresholds{Medium: 200, High: 500, Critical: 1200},
			expected: SeverityMedium,
		},
		{
			name:     "Low severity with p50 above medium 3",
			p50:      220,
			p95:      450,
			p99:      600,
			thresh:   HandshakeRTTThresholds{Medium: 200, High: 500, Critical: 1200},
			expected: SeverityMedium,
		},
		{
			name:     "Medium severity with p50 above medium",
			p50:      220,
			p95:      450,
			p99:      600,
			thresh:   HandshakeRTTThresholds{Medium: 200, High: 500, Critical: 1200},
			expected: SeverityMedium,
		},
		{
			name:     "Low severity with p50 above medium",
			p50:      300,
			p95:      450,
			p99:      600,
			thresh:   HandshakeRTTThresholds{Medium: 200, High: 500, Critical: 1200},
			expected: SeverityLow,
		},
		{
			name:     "Info severity",
			p50:      50,
			p95:      200,
			p99:      400,
			thresh:   HandshakeRTTThresholds{Medium: 200, High: 500, Critical: 1200},
			expected: SeverityInfo,
		},
		{
			name:     "Critical at p99 boundary",
			p50:      150,
			p95:      500,
			p99:      1200,
			thresh:   HandshakeRTTThresholds{Medium: 200, High: 500, Critical: 1200},
			expected: SeverityCritical,
		},
		{
			name:     "High severity with p95 boundary",
			p50:      300,
			p95:      500,
			p99:      1000,
			thresh:   HandshakeRTTThresholds{Medium: 200, High: 500, Critical: 1200},
			expected: SeverityHigh,
		},
		{
			name:     "Medium severity with p50 boundary",
			p50:      200,
			p95:      400,
			p99:      600,
			thresh:   HandshakeRTTThresholds{Medium: 200, High: 500, Critical: 1200},
			expected: SeverityMedium,
		},
		{
			name:     "Low severity with p50 above medium",
			p50:      300,
			p95:      450,
			p99:      600,
			thresh:   HandshakeRTTThresholds{Medium: 200, High: 500, Critical: 1200},
			expected: SeverityMedium,
		},
		{
			name:     "Low severity with p50 above medium",
			p50:      300,
			p95:      450,
			p99:      600,
			thresh:   HandshakeRTTThresholds{Medium: 200, High: 500, Critical: 1200},
			expected: SeverityLow,
		},
		{
			name:     "Info severity with all values low",
			p50:      50,
			p95:      200,
			p99:      400,
			thresh:   HandshakeRTTThresholds{Medium: 200, High: 500, Critical: 1200},
			expected: SeverityInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComputeSeverityForHandshakeRTT(tt.p50, tt.p95, tt.p99, tt.thresh)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestComputeSeverityForDNSRTT(t *testing.T) {
	tests := []struct {
		name     string
		p50      float64
		p95      float64
		p99      float64
		thresh   DNSRTTThresholds
		expected Severity
	}{
		{
			name:     "Critical severity",
			p50:      150,
			p95:      400,
			p99:      1000,
			thresh:   DNSRTTThresholds{Medium: 150, High: 400, Critical: 1000},
			expected: SeverityCritical,
		},
		{
			name:     "Medium severity with p50 above medium",
			p50:      175,
			p95:      300,
			p99:      400,
			thresh:   DNSRTTThresholds{Medium: 150, High: 400, Critical: 1000},
			expected: SeverityMedium,
		},
		{
			name:     "Medium severity",
			p50:      200,
			p95:      350,
			p99:      500,
			thresh:   DNSRTTThresholds{Medium: 150, High: 400, Critical: 1000},
			expected: SeverityMedium,
		},
		{
			name:     "Medium severity with p50 above medium",
			p50:      175,
			p95:      300,
			p99:      400,
			thresh:   DNSRTTThresholds{Medium: 150, High: 400, Critical: 1000},
			expected: SeverityMedium,
		},
		{
			name:     "Info severity",
			p50:      50,
			p95:      200,
			p99:      300,
			thresh:   DNSRTTThresholds{Medium: 150, High: 400, Critical: 1000},
			expected: SeverityInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComputeSeverityForDNSRTT(tt.p50, tt.p95, tt.p99, tt.thresh)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestComputeSeverityForIncompleteHandshakes(t *testing.T) {
	tests := []struct {
		name     string
		count    int
		rate     float64
		thresh   IncompleteHandshakeThresholds
		expected Severity
	}{
		{
			name:     "High severity with high count",
			count:    150,
			rate:     0.18,
			thresh:   IncompleteHandshakeThresholds{Medium: 0.20, High: 0.15},
			expected: SeverityHigh,
		},
		{
			name:     "High severity with high rate",
			count:    0,
			rate:     0.18,
			thresh:   IncompleteHandshakeThresholds{Medium: 0.20, High: 0.15},
			expected: SeverityHigh,
		},
		{
			name:     "High severity with count above threshold",
			count:    100,
			rate:     0.03,
			thresh:   IncompleteHandshakeThresholds{Medium: 0.20, High: 0.15},
			expected: SeverityHigh,
		},
		{
			name:     "High severity with count above threshold 2",
			count:    100,
			rate:     0.03,
			thresh:   IncompleteHandshakeThresholds{Medium: 0.20, High: 0.15},
			expected: SeverityHigh,
		},
		{
			name:     "High severity with high rate",
			count:    0,
			rate:     0.18,
			thresh:   IncompleteHandshakeThresholds{Medium: 0.20, High: 0.15},
			expected: SeverityHigh,
		},
		{
			name:     "High severity with high count",
			count:    100,
			rate:     0.03,
			thresh:   IncompleteHandshakeThresholds{Medium: 0.20, High: 0.15},
			expected: SeverityHigh,
		},
		{
			name:     "Medium severity with medium count and rate",
			count:    30,
			rate:     0.08,
			thresh:   IncompleteHandshakeThresholds{Medium: 0.20, High: 0.15},
			expected: SeverityMedium,
		},
		{
			name:     "Low severity with low count and rate",
			count:    15,
			rate:     0.02,
			thresh:   IncompleteHandshakeThresholds{Medium: 0.20, High: 0.15},
			expected: SeverityLow,
		},
		{
			name:     "Info severity with low count and rate",
			count:    2,
			rate:     0.005,
			thresh:   IncompleteHandshakeThresholds{Medium: 0.20, High: 0.15},
			expected: SeverityInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComputeSeverityForIncompleteHandshakes(tt.count, tt.rate, tt.thresh)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestComputeSeverityForTCPResets(t *testing.T) {
	tests := []struct {
		name     string
		count    int
		rate     float64
		thresh   TCPResetThresholds
		expected Severity
	}{
		{
			name:     "Critical severity with high count",
			count:    10,
			rate:     0.1,
			thresh:   TCPResetThresholds{Medium: 5.0, High: 20.0},
			expected: SeverityCritical,
		},
		{
			name:     "Critical severity with high rate",
			count:    0,
			rate:     1.0,
			thresh:   TCPResetThresholds{Medium: 5.0, High: 20.0},
			expected: SeverityCritical,
		},
		{
			name:     "Critical severity with another high rate",
			count:    0,
			rate:     1.0,
			thresh:   TCPResetThresholds{Medium: 5.0, High: 20.0},
			expected: SeverityCritical,
		},
		{
			name:     "Critical severity with medium rate",
			count:    0,
			rate:     0.5,
			thresh:   TCPResetThresholds{Medium: 5.0, High: 20.0},
			expected: SeverityHigh,
		},
		{
			name:     "Critical severity with medium count",
			count:    5,
			rate:     0.1,
			thresh:   TCPResetThresholds{Medium: 5.0, High: 20.0},
			expected: SeverityHigh,
		},
		{
			name:     "High severity with count",
			count:    2,
			rate:     0.0,
			thresh:   TCPResetThresholds{Medium: 5.0, High: 20.0},
			expected: SeverityLow,
		},
		{
			name:     "High severity with rate",
			count:    0,
			rate:     0.1,
			thresh:   TCPResetThresholds{Medium: 5.0, High: 20.0},
			expected: SeverityLow,
		},
		{
			name:     "High severity with both count and rate",
			count:    1,
			rate:     0.05,
			thresh:   TCPResetThresholds{Medium: 5.0, High: 20.0},
			expected: SeverityInfo,
		},
		{
			name:     "High severity with count and rate 2",
			count:    1,
			rate:     0.05,
			thresh:   TCPResetThresholds{Medium: 5.0, High: 20.0},
			expected: SeverityInfo,
		},
		{
			name:     "High severity with count and rate 3",
			count:    1,
			rate:     0.05,
			thresh:   TCPResetThresholds{Medium: 5.0, High: 20.0},
			expected: SeverityInfo,
		},
		{
			name:     "Info severity with no resets",
			count:    0,
			rate:     0.0,
			thresh:   TCPResetThresholds{Medium: 5.0, High: 20.0},
			expected: SeverityInfo,
		},
		{
			name:     "Info severity with very low rate",
			count:    0,
			rate:     0.02,
			thresh:   TCPResetThresholds{Medium: 5.0, High: 20.0},
			expected: SeverityInfo,
		},
		{
			name:     "Info severity with very low rate 2",
			count:    0,
			rate:     0.01,
			thresh:   TCPResetThresholds{Medium: 5.0, High: 20.0},
			expected: SeverityInfo,
		},
		{
			name:     "Low severity with low count",
			count:    2,
			rate:     0.0,
			thresh:   TCPResetThresholds{Medium: 5.0, High: 20.0},
			expected: SeverityLow,
		},
		{
			name:     "Low severity with low rate",
			count:    0,
			rate:     0.1,
			thresh:   TCPResetThresholds{Medium: 5.0, High: 20.0},
			expected: SeverityLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComputeSeverityForTCPResets(tt.count, tt.rate, tt.thresh)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

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
			thresh:   RetransmissionThresholds{Medium: 0.04, High: 0.08},
			expected: SeverityCritical,
		},
		{
			name:     "High severity",
			rate:     0.08,
			thresh:   RetransmissionThresholds{Medium: 0.04, High: 0.08},
			expected: SeverityHigh,
		},
		{
			name:     "Low severity at threshold",
			rate:     0.045,
			thresh:   RetransmissionThresholds{Medium: 0.04, High: 0.08},
			expected: SeverityLow,
		},
		{
			name:     "Medium severity below low threshold",
			rate:     0.03,
			thresh:   RetransmissionThresholds{Medium: 0.04, High: 0.08},
			expected: SeverityMedium,
		},
		{
			name:     "Info severity below low threshold",
			rate:     0.01,
			thresh:   RetransmissionThresholds{Medium: 0.04, High: 0.08},
			expected: SeverityInfo,
		},
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

func TestComputeSeverityForDNSFailures(t *testing.T) {
	tests := []struct {
		name     string
		count    int
		rate     float64
		thresh   DNSFailureThresholds
		expected Severity
	}{
		{
			name:     "Critical severity with high count",
			count:    25,
			rate:     0.12,
			thresh:   DNSFailureThresholds{Medium: 0.02, High: 0.10},
			expected: SeverityCritical,
		},
		{
			name:     "Critical severity with high rate",
			count:    0,
			rate:     0.15,
			thresh:   DNSFailureThresholds{Medium: 0.02, High: 0.10},
			expected: SeverityCritical,
		},
		{
			name:     "High severity with high count",
			count:    22,
			rate:     0.12,
			thresh:   DNSFailureThresholds{Medium: 0.02, High: 0.10},
			expected: SeverityHigh,
		},
		{
			name:     "High severity with high rate",
			count:    0,
			rate:     0.10,
			thresh:   DNSFailureThresholds{Medium: 0.02, High: 0.10},
			expected: SeverityHigh,
		},
		{
			name:     "Medium severity with medium count",
			count:    8,
			rate:     0.05,
			thresh:   DNSFailureThresholds{Medium: 0.02, High: 0.10},
			expected: SeverityMedium,
		},
		{
			name:     "Medium severity with medium rate",
			count:    0,
			rate:     0.05,
			thresh:   DNSFailureThresholds{Medium: 0.02, High: 0.10},
			expected: SeverityMedium,
		},
		{
			name:     "Low severity with low count",
			count:    3,
			rate:     0.015,
			thresh:   DNSFailureThresholds{Medium: 0.02, High: 0.10},
			expected: SeverityLow,
		},
		{
			name:     "Low severity with low rate",
			count:    0,
			rate:     0.015,
			thresh:   DNSFailureThresholds{Medium: 0.02, High: 0.10},
			expected: SeverityLow,
		},
		{
			name:     "Info severity with low values",
			count:    1,
			rate:     0.005,
			thresh:   DNSFailureThresholds{Medium: 0.02, High: 0.10},
			expected: SeverityInfo,
		},
		{
			name:     "Info severity with very low values",
			count:    0,
			rate:     0.005,
			thresh:   DNSFailureThresholds{Medium: 0.02, High: 0.10},
			expected: SeverityInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComputeSeverityForDNSFailures(tt.count, tt.rate, tt.thresh)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestMaxSeverity(t *testing.T) {
	tests := []struct {
		name     string
		severals []Severity
		expected Severity
	}{
		{
			name:     "Max of mixed severities",
			severals: []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical},
			expected: SeverityCritical,
		},
		{
			name:     "Max of same severity",
			severals: []Severity{SeverityInfo, SeverityInfo, SeverityInfo},
			expected: SeverityInfo,
		},
		{
			name:     "Max with single severity",
			severals: []Severity{SeverityHigh},
			expected: SeverityHigh,
		},
		{
			name:     "Max with empty slice",
			severals: []Severity{},
			expected: SeverityInfo,
		},
		{
			name:     "Max with only critical",
			severals: []Severity{SeverityCritical, SeverityCritical, SeverityCritical},
			expected: SeverityCritical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaxSeverity(tt.severals...)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}
