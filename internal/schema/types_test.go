package schema

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNewResult(t *testing.T) {
	start := time.Now()
	end := start.Add(10 * time.Second)

	result := NewResult(RunModePCAP, "wan", start, end, 10)

	if result.SchemaVersion != SchemaVersion {
		t.Errorf("Schema version mismatch: got %s, want %s", result.SchemaVersion, SchemaVersion)
	}

	if result.Tool.Name != ToolName {
		t.Errorf("Tool name mismatch: got %s, want %s", result.Tool.Name, ToolName)
	}

	if result.Run.Mode != RunModePCAP {
		t.Errorf("Mode mismatch: got %s, want %s", result.Run.Mode, RunModePCAP)
	}

	if result.Run.Profile != "wan" {
		t.Errorf("Profile mismatch: got %s, want wan", result.Run.Profile)
	}

	if result.Summary.Severity != SeverityInfo {
		t.Errorf("Initial severity should be info, got %s", result.Summary.Severity)
	}

	if result.Summary.SignalsTriggered != 0 {
		t.Errorf("Initial signals triggered should be 0, got %d", result.Summary.SignalsTriggered)
	}

	if result.Metrics.FlowsTotal != 0 {
		t.Errorf("Initial flows total should be 0, got %d", result.Metrics.FlowsTotal)
	}
}

func TestNewTCPMetrics(t *testing.T) {
	metrics := NewTCPMetrics()

	if metrics.SynTotal != 0 {
		t.Errorf("SynTotal should be 0, got %d", metrics.SynTotal)
	}

	if metrics.IncompleteHandshakes.Count != 0 {
		t.Errorf("IncompleteHandshakes.Count should be 0, got %d", metrics.IncompleteHandshakes.Count)
	}

	if metrics.IncompleteHandshakes.Severity != SeverityInfo {
		t.Errorf("Initial incomplete handshake severity should be info, got %s", metrics.IncompleteHandshakes.Severity)
	}

	if metrics.Resets.Count != 0 {
		t.Errorf("Resets.Count should be 0, got %d", metrics.Resets.Count)
	}

	if metrics.Latency.HandshakeRTTms.P50 != 0 {
		t.Errorf("P50 should be 0, got %d", metrics.Latency.HandshakeRTTms.P50)
	}
}

func TestNewDNSMetrics(t *testing.T) {
	metrics := NewDNSMetrics()

	if metrics.Queries != 0 {
		t.Errorf("Queries should be 0, got %d", metrics.Queries)
	}

	if metrics.Failures.Count != 0 {
		t.Errorf("Failures.Count should be 0, got %d", metrics.Failures.Count)
	}

	if metrics.Failures.Severity != SeverityInfo {
		t.Errorf("Initial failure severity should be info, got %s", metrics.Failures.Severity)
	}

	if metrics.LatencyRTTms.P50 != 0 {
		t.Errorf("P50 should be 0, got %d", metrics.LatencyRTTms.P50)
	}
}

func TestNewAnomalyMetrics(t *testing.T) {
	metrics := NewAnomalyMetrics()

	if metrics.SynScanSuspects.Count != 0 {
		t.Errorf("SynScanSuspects.Count should be 0, got %d", metrics.SynScanSuspects.Count)
	}

	if len(metrics.SynScanSuspects.Top) != 0 {
		t.Errorf("SynScanSuspects.Top should be empty, got %d items", len(metrics.SynScanSuspects.Top))
	}

	if metrics.DNSNxdomainClients.Count != 0 {
		t.Errorf("DNSNxdomainClients.Count should be 0, got %d", metrics.DNSNxdomainClients.Count)
	}

	if len(metrics.DNSNxdomainClients.Top) != 0 {
		t.Errorf("DNSNxdomainClients.Top should be empty, got %d items", len(metrics.DNSNxdomainClients.Top))
	}
}

func TestAddError(t *testing.T) {
	result := NewResult(RunModePCAP, "wan", time.Now(), time.Now().Add(1*time.Second), 1)
	AddError(&result, "TEST_ERROR", "Test error message")

	if len(result.Errors) != 1 {
		t.Errorf("Should have 1 error, got %d", len(result.Errors))
	}

	if result.Errors[0].Code != "TEST_ERROR" {
		t.Errorf("Error code mismatch: got %s, want TEST_ERROR", result.Errors[0].Code)
	}

	if result.Errors[0].Message != "Test error message" {
		t.Errorf("Error message mismatch: got %s, want Test error message", result.Errors[0].Message)
	}
}

func TestAddSourceTopTalker(t *testing.T) {
	result := NewResult(RunModePCAP, "wan", time.Now(), time.Now().Add(1*time.Second), 1)
	result.TopTalkers.AddSource("192.168.1.1", 10, 1000)
	result.TopTalkers.AddSource("192.168.1.2", 5, 500)

	if len(result.TopTalkers.Sources) != 2 {
		t.Errorf("Should have 2 sources, got %d", len(result.TopTalkers.Sources))
	}

	if result.TopTalkers.Sources[0].IP != "192.168.1.1" {
		t.Errorf("First source should be 192.168.1.1, got %s", result.TopTalkers.Sources[0].IP)
	}

	if result.TopTalkers.Sources[0].NewConnections != 10 {
		t.Errorf("First source connections should be 10, got %d", result.TopTalkers.Sources[0].NewConnections)
	}
}

func TestAddDestinationTopTalker(t *testing.T) {
	result := NewResult(RunModePCAP, "wan", time.Now(), time.Now().Add(1*time.Second), 1)
	result.TopTalkers.AddDestination("192.168.1.1", 10, 1000)
	result.TopTalkers.AddDestination("192.168.1.2", 5, 500)

	if len(result.TopTalkers.Destinations) != 2 {
		t.Errorf("Should have 2 destinations, got %d", len(result.TopTalkers.Destinations))
	}

	if result.TopTalkers.Destinations[0].IP != "192.168.1.1" {
		t.Errorf("First destination should be 192.168.1.1, got %s", result.TopTalkers.Destinations[0].IP)
	}

	if result.TopTalkers.Destinations[0].NewConnections != 10 {
		t.Errorf("First destination connections should be 10, got %d", result.TopTalkers.Destinations[0].NewConnections)
	}
}

func TestSortAndLimit(t *testing.T) {
	talkers := []TopTalker{
		{IP: "192.168.1.2", NewConnections: 5, Bytes: 500},
		{IP: "192.168.1.1", NewConnections: 10, Bytes: 1000},
		{IP: "192.168.1.3", NewConnections: 3, Bytes: 300},
	}

	limited := sortAndLimit(talkers, 2)

	if len(limited) != 2 {
		t.Errorf("Should have 2 items after limiting, got %d", len(limited))
	}

	if limited[0].NewConnections != 10 || limited[0].IP != "192.168.1.1" {
		t.Errorf("First item should be 192.168.1.1 with 10 connections, got %+v", limited[0])
	}

	if limited[1].NewConnections != 5 || limited[1].IP != "192.168.1.2" {
		t.Errorf("Second item should be 192.168.1.2 with 5 connections, got %+v", limited[1])
	}
}

func TestSortAndLimitNoLimit(t *testing.T) {
	talkers := []TopTalker{
		{IP: "192.168.1.2", NewConnections: 5, Bytes: 500},
		{IP: "192.168.1.1", NewConnections: 10, Bytes: 1000},
		{IP: "192.168.1.3", NewConnections: 3, Bytes: 300},
	}

	limited := sortAndLimit(talkers, 0)

	if len(limited) != 0 {
		t.Errorf("Should have 0 items when limit is 0, got %d", len(limited))
	}
}

func TestSortAndLimitLessThanTotal(t *testing.T) {
	talkers := []TopTalker{
		{IP: "192.168.1.2", NewConnections: 5, Bytes: 500},
		{IP: "192.168.1.1", NewConnections: 10, Bytes: 1000},
		{IP: "192.168.1.3", NewConnections: 3, Bytes: 300},
	}

	limited := sortAndLimit(talkers, 5)

	if len(limited) != 3 {
		t.Errorf("Should have 3 items when limit >= total, got %d", len(limited))
	}
}

func TestAddCompletionSeverity(t *testing.T) {
	result := NewResult(RunModePCAP, "wan", time.Now(), time.Now().Add(1*time.Second), 1)

	result.AddCompletionSeverity(SeverityLow)
	if result.Summary.Severity != SeverityLow {
		t.Errorf("Severity should be low, got %s", result.Summary.Severity)
	}

	result.AddCompletionSeverity(SeverityMedium)
	if result.Summary.Severity != SeverityMedium {
		t.Errorf("Severity should be medium, got %s", result.Summary.Severity)
	}

	result.AddCompletionSeverity(SeverityCritical)
	if result.Summary.Severity != SeverityCritical {
		t.Errorf("Severity should be critical, got %s", result.Summary.Severity)
	}
}

func TestAddSignalTriggered(t *testing.T) {
	result := NewResult(RunModePCAP, "wan", time.Now(), time.Now().Add(1*time.Second), 1)

	result.AddSignalTriggered()
	if result.Summary.SignalsTriggered != 1 {
		t.Errorf("Signals triggered should be 1, got %d", result.Summary.SignalsTriggered)
	}

	result.AddSignalTriggered()
	if result.Summary.SignalsTriggered != 2 {
		t.Errorf("Signals triggered should be 2, got %d", result.Summary.SignalsTriggered)
	}
}

func TestSetPcapFile(t *testing.T) {
	result := NewResult(RunModePCAP, "wan", time.Now(), time.Now().Add(1*time.Second), 1)
	result.SetPcapFile("test.pcap")

	if result.Run.Input.PcapFile != "test.pcap" {
		t.Errorf("Pcap file should be test.pcap, got %s", result.Run.Input.PcapFile)
	}
}

func TestSetCaptureInterface(t *testing.T) {
	result := NewResult(RunModeCapture, "wan", time.Now(), time.Now().Add(1*time.Second), 1)
	result.SetCaptureInterface("eth0")

	if result.Run.Capture.Iface != "eth0" {
		t.Errorf("Interface should be eth0, got %s", result.Run.Capture.Iface)
	}
}

func TestSetCaptureBPF(t *testing.T) {
	result := NewResult(RunModeCapture, "wan", time.Now(), time.Now().Add(1*time.Second), 1)
	result.SetCaptureBPF("tcp port 80")

	if result.Run.Capture.BPF != "tcp port 80" {
		t.Errorf("BPF should be tcp port 80, got %s", result.Run.Capture.BPF)
	}
}

func TestSetVersion(t *testing.T) {
	result := NewResult(RunModePCAP, "wan", time.Now(), time.Now().Add(1*time.Second), 1)
	result.SetVersion("1.0.0")

	if result.Tool.Version != "1.0.0" {
		t.Errorf("Version should be 1.0.0, got %s", result.Tool.Version)
	}
}

func TestNormalizeFlowKeyBidirectional(t *testing.T) {
	key := NormalizeFlowKey("192.168.1.1", 12345, "8.8.8.8", 53)
	expected := "192.168.1.1:12345-8.8.8.8:53"

	if key != expected {
		t.Errorf("Flow key should be %s, got %s", expected, key)
	}
}

func TestNormalizeFlowKeyReversed(t *testing.T) {
	key := NormalizeFlowKey("8.8.8.8", 53, "192.168.1.1", 12345)
	expected := "192.168.1.1:12345-8.8.8.8:53"

	if key != expected {
		t.Errorf("Flow key should be %s, got %s", expected, key)
	}
}

func TestNormalizeFlowKeySameIP(t *testing.T) {
	key1 := NormalizeFlowKey("192.168.1.1", 12345, "192.168.1.1", 8080)
	key2 := NormalizeFlowKey("192.168.1.1", 8080, "192.168.1.1", 12345)

	if key1 != key2 {
		t.Errorf("Flow keys should be equal when same endpoints: %s != %s", key1, key2)
	}
}

func TestGetPercentile(t *testing.T) {
	values := []int{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}

	p50 := GetPercentile(values, 0.50)
	if p50 != 50 {
		t.Errorf("P50 should be 50, got %d", p50)
	}

	p95 := GetPercentile(values, 0.95)
	if p95 != 90 {
		t.Errorf("P95 should be 90, got %d", p95)
	}

	p99 := GetPercentile(values, 0.99)
	if p99 != 90 {
		t.Errorf("P99 should be 90, got %d", p99)
	}
}

func TestGetPercentileEmpty(t *testing.T) {
	values := []int{}
	p50 := GetPercentile(values, 0.50)

	if p50 != 0 {
		t.Errorf("P50 should be 0 for empty list, got %d", p50)
	}
}

func TestGetPercentileOutOfBounds(t *testing.T) {
	values := []int{10, 20, 30}

	p95 := GetPercentile(values, 0.95)
	if p95 != 20 {
		t.Errorf("P95 should be 20 (middle value) for small list, got %d", p95)
	}

	p99 := GetPercentile(values, 0.99)
	if p99 != 20 {
		t.Errorf("P99 should be 20 (middle value) for small list, got %d", p99)
	}
}

func TestAddAnomalySuspect(t *testing.T) {
	result := NewResult(RunModePCAP, "wan", time.Now(), time.Now().Add(1*time.Second), 1)
	result.AddAnomalySuspect("192.168.1.100", 100, 90)

	if len(result.Metrics.Anomalies.SynScanSuspects.Top) != 1 {
		t.Errorf("Should have 1 suspect, got %d", len(result.Metrics.Anomalies.SynScanSuspects.Top))
	}

	suspect := result.Metrics.Anomalies.SynScanSuspects.Top[0]
	if suspect.IP != "192.168.1.100" {
		t.Errorf("IP should be 192.168.1.100, got %s", suspect.IP)
	}

	if suspect.Syn != 100 {
		t.Errorf("Syn should be 100, got %d", suspect.Syn)
	}

	if suspect.Completed != 90 {
		t.Errorf("Completed should be 90, got %d", suspect.Completed)
	}

	expectedRate := 90.0
	if suspect.CompletionRatePercent != expectedRate {
		t.Errorf("Completion rate should be %.2f, got %.2f", expectedRate, suspect.CompletionRatePercent)
	}

	if result.Metrics.Anomalies.SynScanSuspects.Count != 1 {
		t.Errorf("Count should be 1, got %d", result.Metrics.Anomalies.SynScanSuspects.Count)
	}
}

func TestAddAnomalySuspectZeroSyn(t *testing.T) {
	result := NewResult(RunModePCAP, "wan", time.Now(), time.Now().Add(1*time.Second), 1)
	result.AddAnomalySuspect("192.168.1.100", 0, 0)

	if len(result.Metrics.Anomalies.SynScanSuspects.Top) != 1 {
		t.Errorf("Should have 1 suspect, got %d", len(result.Metrics.Anomalies.SynScanSuspects.Top))
	}

	suspect := result.Metrics.Anomalies.SynScanSuspects.Top[0]
	if suspect.CompletionRatePercent != 0 {
		t.Errorf("Completion rate should be 0 for zero syn, got %.2f", suspect.CompletionRatePercent)
	}
}

func TestAddDNSNxdomainClient(t *testing.T) {
	result := NewResult(RunModePCAP, "wan", time.Now(), time.Now().Add(1*time.Second), 1)
	result.AddDNSNxdomainClient("192.168.1.100", 50, 10)

	if len(result.Metrics.Anomalies.DNSNxdomainClients.Top) != 1 {
		t.Errorf("Should have 1 client, got %d", len(result.Metrics.Anomalies.DNSNxdomainClients.Top))
	}

	client := result.Metrics.Anomalies.DNSNxdomainClients.Top[0]
	if client.IP != "192.168.1.100" {
		t.Errorf("IP should be 192.168.1.100, got %s", client.IP)
	}

	if client.Queries != 50 {
		t.Errorf("Queries should be 50, got %d", client.Queries)
	}

	if client.NXDOMAIN != 10 {
		t.Errorf("NXDOMAIN should be 10, got %d", client.NXDOMAIN)
	}

	expectedRate := 20.0
	if client.NXDomainRatePercent != expectedRate {
		t.Errorf("NXDomain rate should be %.2f, got %.2f", expectedRate, client.NXDomainRatePercent)
	}

	if result.Metrics.Anomalies.DNSNxdomainClients.Count != 1 {
		t.Errorf("Count should be 1, got %d", result.Metrics.Anomalies.DNSNxdomainClients.Count)
	}
}

func TestJSONSerialization(t *testing.T) {
	start := time.Now()
	end := start.Add(10 * time.Second)

	result := NewResult(RunModePCAP, "wan", start, end, 10)
	result.SetPcapFile("test.pcap")
	result.SetVersion("1.0.0")

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Failed to marshal result: %v", err)
	}

	var unmarshaled Result
	if err := json.Unmarshal(jsonBytes, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if unmarshaled.SchemaVersion != result.SchemaVersion {
		t.Errorf("Schema version mismatch: got %s, want %s", unmarshaled.SchemaVersion, result.SchemaVersion)
	}

	if unmarshaled.Tool.Version != result.Tool.Version {
		t.Errorf("Version mismatch: got %s, want %s", unmarshaled.Tool.Version, result.Tool.Version)
	}

	if unmarshaled.Run.Mode != result.Run.Mode {
		t.Errorf("Mode mismatch: got %s, want %s", unmarshaled.Run.Mode, result.Run.Mode)
	}
}

func TestJSONHasRequiredFields(t *testing.T) {
	start := time.Now()
	end := start.Add(10 * time.Second)

	result := NewResult(RunModePCAP, "wan", start, end, 10)

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Failed to marshal result: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	requiredFields := []string{
		"schema_version", "tool", "run", "summary", "metrics",
		"top_talkers", "errors", "help",
	}

	for _, field := range requiredFields {
		if _, exists := decoded[field]; !exists {
			t.Errorf("Missing required field: %s", field)
		}
	}
}

func TestJSONPrettyVsCompact(t *testing.T) {
	start := time.Now()
	end := start.Add(10 * time.Second)

	result := NewResult(RunModePCAP, "wan", start, end, 10)

	compact, err := result.String()
	if err != nil {
		t.Fatalf("Failed to get compact JSON: %v", err)
	}

	pretty, err := result.PrettyString()
	if err != nil {
		t.Fatalf("Failed to get pretty JSON: %v", err)
	}

	if len(compact) >= len(pretty) {
		t.Errorf("Compact JSON should be shorter or equal to pretty JSON")
	}

	var compactMap, prettyMap map[string]interface{}
	if err := json.Unmarshal([]byte(compact), &compactMap); err != nil {
		t.Fatalf("Failed to unmarshal compact JSON: %v", err)
	}

	if err := json.Unmarshal([]byte(pretty), &prettyMap); err != nil {
		t.Fatalf("Failed to unmarshal pretty JSON: %v", err)
	}

	if compactMap["schema_version"] != prettyMap["schema_version"] {
		t.Errorf("Schema version should be the same in both formats")
	}
}
