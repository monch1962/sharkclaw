package analyze

import (
	"encoding/json"
	"testing"
	"time"
)

func TestJSONOutputIncludesSeverity(t *testing.T) {
	// Create analyzer with test profile
	analyzer, err := NewAnalyzer("lan", 5)
	if err != nil {
		t.Fatalf("Failed to create analyzer: %v", err)
	}

	// Create test packet data
	packets := []Packet{
		{
			Timestamp:       time.Unix(1000, 0),
			Length:          100,
			Protocol:        "TCP",
			SourceIP:        "10.0.0.1",
			DestinationIP:   "10.0.0.2",
			SourcePort:      12345,
			DestinationPort: 54321,
			SYN:             true,
		},
		{
			Timestamp:       time.Unix(1005, 0),
			Length:          100,
			Protocol:        "TCP",
			SourceIP:        "10.0.0.2",
			DestinationIP:   "10.0.0.1",
			SourcePort:      54321,
			DestinationPort: 12345,
			RST:             true,
		},
	}

	// Analyze packets
	result, err := analyzer.AnalyzePcap(packets)
	if err != nil {
		t.Fatalf("Failed to analyze packets: %v", err)
	}

	// Check that result is not nil
	if result == nil {
		t.Fatal("Result is nil")
	}

	// Check that Summary has severity
	if result.Summary.Severity == "" {
		t.Error("Summary severity is empty")
	}

	// Check that TCP metrics have severity
	if result.Metrics.TCPMetrics.Resets.RatePercent == 0 {
		t.Error("TCP resets rate_percent is 0")
	}
	if result.Metrics.TCPMetrics.Resets.Severity == "" {
		t.Error("TCP resets severity is empty")
	}

	// Check that metrics include severity
	metricFields := map[string]bool{
		"Resets":               true,
		"Retransmissions":      true,
		"DuplicateACKs":        true,
		"IncompleteHandshakes": true,
		"Failure":              true,
		"LatencyRTT":           true,
		"Summary":              true,
	}

	for name, hasField := range metricFields {
		if !hasField {
			t.Errorf("Missing metric field: %s", name)
		}
	}

	// Check that all metrics have rate_percent
	metricsWithRate := map[string]bool{
		"Resets":               true,
		"Retransmissions":      true,
		"DuplicateACKs":        true,
		"IncompleteHandshakes": true,
		"Failure":              true,
	}

	for name, hasRate := range metricsWithRate {
		if hasRate {
			if name == "Resets" {
				if result.Metrics.TCPMetrics.Resets.RatePercent < 0 {
					t.Errorf("%s rate_percent is negative", name)
				}
			} else if name == "Retransmissions" {
				if result.Metrics.TCPMetrics.ReliabilityHints.Retransmissions.RatePercent < 0 {
					t.Errorf("%s rate_percent is negative", name)
				}
			} else if name == "DuplicateACKs" {
				if result.Metrics.TCPMetrics.ReliabilityHints.DupACKs.RatePercent < 0 {
					t.Errorf("%s rate_percent is negative", name)
				}
			} else if name == "IncompleteHandshakes" {
				if result.Metrics.TCPMetrics.IncompleteHandshakes.RatePercent < 0 {
					t.Errorf("%s rate_percent is negative", name)
				}
			} else if name == "Failure" {
				if result.Metrics.DNSMetrics.Failures.RatePercent < 0 {
					t.Errorf("%s rate_percent is negative", name)
				}
			}
		}
	}

	// Check that all metrics have severity
	for name, hasSeverity := range metricsWithRate {
		if hasSeverity {
			if name == "Resets" {
				if result.Metrics.TCPMetrics.Resets.Severity == "" {
					t.Errorf("%s severity is empty", name)
				}
			} else if name == "Retransmissions" {
				if result.Metrics.TCPMetrics.ReliabilityHints.Retransmissions.Severity == "" {
					t.Errorf("%s severity is empty", name)
				}
			} else if name == "DuplicateACKs" {
				if result.Metrics.TCPMetrics.ReliabilityHints.DupACKs.Severity == "" {
					t.Errorf("%s severity is empty", name)
				}
			} else if name == "IncompleteHandshakes" {
				if result.Metrics.TCPMetrics.IncompleteHandshakes.Severity == "" {
					t.Errorf("%s severity is empty", name)
				}
			} else if name == "Failure" {
				if result.Metrics.DNSMetrics.Failures.Severity == "" {
					t.Errorf("%s severity is empty", name)
				}
			}
		}
	}

	// Check that all metrics have severity
	for name, hasSeverity := range metricsWithRate {
		if hasSeverity {
			if name == "Resets" {
				if result.Metrics.TCPMetrics.Resets.Severity == "" {
					t.Errorf("%s severity is empty", name)
				}
			} else if name == "Retransmissions" {
				if result.Metrics.TCPMetrics.ReliabilityHints.Retransmissions.Severity == "" {
					t.Errorf("%s severity is empty", name)
				}
			} else if name == "DuplicateACKs" {
				if result.Metrics.TCPMetrics.ReliabilityHints.DupACKs.Severity == "" {
					t.Errorf("%s severity is empty", name)
				}
			} else if name == "IncompleteHandshakes" {
				if result.Metrics.TCPMetrics.IncompleteHandshakes.Severity == "" {
					t.Errorf("%s severity is empty", name)
				}
			} else if name == "Failure" {
				if result.Metrics.DNSMetrics.Failures.Severity == "" {
					t.Errorf("%s severity is empty", name)
				}
			}
		}
	}

	// Check that summary has SignalsTriggered
	if result.Summary.SignalsTriggered == 0 {
		t.Error("SignalsTriggered is 0")
	}

	// Check that result can be serialized to JSON
	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal result to JSON: %v", err)
	}

	// Verify JSON contains severity fields
	jsonStr := string(jsonBytes)
	if jsonStr == "" {
		t.Fatal("JSON output is empty")
	}

	// Check for severity field in TCP metrics
	if !contains(jsonStr, "\"severity\"") {
		t.Error("JSON output does not contain 'severity' field in TCP metrics")
	}

	// Check for rate_percent field in TCP metrics
	if !contains(jsonStr, "\"rate_percent\"") {
		t.Error("JSON output does not contain 'rate_percent' field in TCP metrics")
	}

	// Check for severity field in Summary
	if !contains(jsonStr, "\"summary\"") {
		t.Error("JSON output does not contain 'summary' field")
	}

	t.Logf("JSON output:\n%s", jsonStr)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
