package analyze

import (
	"testing"
	"time"
)

func TestNewAnalyzer(t *testing.T) {
	tests := []struct {
		name        string
		profile     string
		includeTopN int
		wantErr     bool
	}{
		{
			name:        "analyzer with valid profile and topN",
			profile:     "wan",
			includeTopN: 5,
			wantErr:     false,
		},
		{
			name:        "analyzer with invalid profile",
			profile:     "invalid",
			includeTopN: 5,
			wantErr:     true,
		},
		{
			name:        "analyzer with invalid topN",
			profile:     "wan",
			includeTopN: -1,
			wantErr:     true,
		},
		{
			name:        "analyzer with zero topN",
			profile:     "lan",
			includeTopN: 0,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer, err := NewAnalyzer(tt.profile, tt.includeTopN)
			if tt.wantErr {
				if err == nil {
					t.Errorf("NewAnalyzer() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("NewAnalyzer() unexpected error: %v", err)
			}

			if analyzer == nil {
				t.Error("NewAnalyzer() returned nil analyzer")
			}
		})
	}
}

func TestAnalyzePcap(t *testing.T) {
	// Test with mock packet data
	packets := []Packet{
		{
			Timestamp: time.Now(),
			Length:    100,
		},
		{
			Timestamp: time.Now().Add(1 * time.Millisecond),
			Length:    150,
		},
	}

	analyzer, err := NewAnalyzer("wan", 5)
	if err != nil {
		t.Fatalf("Failed to create analyzer: %v", err)
	}

	result, err := analyzer.AnalyzePcap(packets)
	if err != nil {
		t.Errorf("AnalyzePcap() unexpected error: %v", err)
	}

	if result == nil {
		t.Error("AnalyzePcap() returned nil result")
	}

	// Verify result has expected fields
	if result.SchemaVersion == "" {
		t.Error("Result should have schema_version")
	}

	if result.Tool.Name != "sharkclaw" {
		t.Errorf("Result tool name should be sharkclaw, got %s", result.Tool.Name)
	}

	if result.Run.Mode == "" {
		t.Error("Result should have mode")
	}
}

func TestAnalyzeCapture(t *testing.T) {
	// Test with mock packet data
	packets := []Packet{
		{
			Timestamp: time.Now(),
			Length:    100,
		},
		{
			Timestamp: time.Now().Add(1 * time.Millisecond),
			Length:    150,
		},
	}

	analyzer, err := NewAnalyzer("lan", 3)
	if err != nil {
		t.Fatalf("Failed to create analyzer: %v", err)
	}

	result, err := analyzer.AnalyzeCapture(packets, "eth0", 10*time.Second)
	if err != nil {
		t.Errorf("AnalyzeCapture() unexpected error: %v", err)
	}

	if result == nil {
		t.Error("AnalyzeCapture() returned nil result")
	}

	// Verify result has expected fields
	if result.Run.Mode == "" {
		t.Error("Result should have mode")
	}

	if result.Run.Duration == 0 {
		t.Error("Result should have duration")
	}
}

func TestAnalyzerWithTopN(t *testing.T) {
	topNValues := []int{0, 1, 5, 10}
	for _, topN := range topNValues {
		t.Run(string(rune(topN)), func(t *testing.T) {
			analyzer, err := NewAnalyzer("wan", topN)
			if err != nil {
				t.Fatalf("Failed to create analyzer: %v", err)
			}

			packets := []Packet{
				{
					Timestamp: time.Now(),
					Length:    100,
				},
			}

			result, err := analyzer.AnalyzePcap(packets)
			if err != nil {
				t.Errorf("AnalyzePcap() unexpected error: %v", err)
			}

			if result == nil {
				t.Error("AnalyzePcap() returned nil result")
			}
		})
	}
}

func TestAnalyzerWithProfile(t *testing.T) {
	profiles := []string{"lan", "wan"}
	for _, profile := range profiles {
		t.Run(profile, func(t *testing.T) {
			analyzer, err := NewAnalyzer(profile, 5)
			if err != nil {
				t.Fatalf("Failed to create analyzer: %v", err)
			}

			packets := []Packet{
				{
					Timestamp: time.Now(),
					Length:    100,
				},
			}

			result, err := analyzer.AnalyzePcap(packets)
			if err != nil {
				t.Errorf("AnalyzePcap() unexpected error: %v", err)
			}

			if result == nil {
				t.Error("AnalyzePcap() returned nil result")
			}
		})
	}
}
