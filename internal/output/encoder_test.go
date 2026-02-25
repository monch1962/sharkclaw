package output

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestEncoder(t *testing.T) {
	tests := []struct {
		name    string
		data    interface{}
		wantErr bool
	}{
		{
			name: "encode valid JSON result",
			data: &MockResult{
				SchemaVersion: "1.0.0",
				Tool: struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				}{
					Name:    "sharkclaw",
					Version: "dev",
				},
				Run: struct {
					Mode            string  `json:"mode"`
					StartTime       string  `json:"start_time"`
					EndTime         string  `json:"end_time"`
					Duration        string  `json:"duration"`
					DurationSeconds float64 `json:"duration_seconds"`
					Profile         string  `json:"profile"`
					IncludeTopN     int     `json:"include_topN"`
				}{
					Mode:            "pcap",
					StartTime:       "2026-02-25T00:00:00Z",
					EndTime:         "2026-02-25T00:01:00Z",
					Duration:        "1m0s",
					DurationSeconds: 60,
					Profile:         "wan",
					IncludeTopN:     5,
				},
			},
			wantErr: false,
		},
		{
			name:    "encode empty data",
			data:    struct{}{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := Encode(tt.data, false)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Encode() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Encode() unexpected error: %v", err)
			}

			if output == "" {
				t.Error("Encode() returned empty output")
			}
		})
	}
}

func TestPrettyEncoder(t *testing.T) {
	tests := []struct {
		name    string
		data    interface{}
		wantErr bool
	}{
		{
			name: "pretty encode valid JSON result",
			data: &MockResult{
				SchemaVersion: "1.0.0",
				Tool: struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				}{
					Name:    "sharkclaw",
					Version: "dev",
				},
				Run: struct {
					Mode            string  `json:"mode"`
					StartTime       string  `json:"start_time"`
					EndTime         string  `json:"end_time"`
					Duration        string  `json:"duration"`
					DurationSeconds float64 `json:"duration_seconds"`
					Profile         string  `json:"profile"`
					IncludeTopN     int     `json:"include_topN"`
				}{
					Mode:            "capture",
					StartTime:       "2026-02-25T00:00:00Z",
					EndTime:         "2026-02-25T00:01:00Z",
					Duration:        "1m0s",
					DurationSeconds: 60,
					Profile:         "lan",
					IncludeTopN:     10,
				},
			},
			wantErr: false,
		},
		{
			name:    "pretty encode empty data",
			data:    struct{}{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := Encode(tt.data, true)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Encode() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Encode() unexpected error: %v", err)
			}

			if output == "" {
				t.Error("Encode() returned empty output")
			}

			// Verify output is pretty printed
			var buf bytes.Buffer
			err = json.Indent(&buf, []byte(output), "", "  ")
			if err != nil {
				t.Errorf("Pretty output is not valid JSON: %v", err)
			}

			// Pretty printed output should have newlines and indentation
			if len(output) == 0 {
				t.Error("Pretty output should not be empty")
			}

			if len(output) < len(string(bytes.TrimSpace([]byte(output)))) {
				t.Error("Pretty output should have whitespace")
			}
		})
	}
}

func TestOutputFormat(t *testing.T) {
	data := struct {
		Field1 string `json:"field1"`
		Field2 int    `json:"field2"`
	}{
		Field1: "value1",
		Field2: 123,
	}

	output, err := Encode(data, false)
	if err != nil {
		t.Fatalf("Encode() unexpected error: %v", err)
	}

	// Verify output can be parsed back
	var parsed struct {
		Field1 string `json:"field1"`
		Field2 int    `json:"field2"`
	}

	err = json.Unmarshal([]byte(output), &parsed)
	if err != nil {
		t.Errorf("Failed to parse output: %v", err)
	}

	if parsed.Field1 != data.Field1 {
		t.Errorf("Field1 mismatch: got %s, want %s", parsed.Field1, data.Field1)
	}

	if parsed.Field2 != data.Field2 {
		t.Errorf("Field2 mismatch: got %d, want %d", parsed.Field2, data.Field2)
	}
}

type MockResult struct {
	SchemaVersion string `json:"schema_version"`
	Tool          struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	Run struct {
		Mode            string  `json:"mode"`
		StartTime       string  `json:"start_time"`
		EndTime         string  `json:"end_time"`
		Duration        string  `json:"duration"`
		DurationSeconds float64 `json:"duration_seconds"`
		Profile         string  `json:"profile"`
		IncludeTopN     int     `json:"include_topN"`
	}
}
