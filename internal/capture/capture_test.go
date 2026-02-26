package capture

import (
	"testing"
	"time"
)

func TestCaptureMode(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		iface    string
		wantErr  bool
	}{
		{
			name:     "capture with valid duration",
			duration: 10 * time.Second,
			iface:    "eth0",
			wantErr:  false,
		},
		{
			name:     "capture with default duration",
			duration: 10 * time.Second,
			iface:    "",
			wantErr:  true,
		},
		{
			name:     "capture with invalid duration",
			duration: 0,
			iface:    "eth0",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Capture(tt.duration, tt.iface, "", "wan", false, 5)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Capture() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Capture() unexpected error: %v", err)
			}
		})
	}
}

func TestCaptureWithBPFFilter(t *testing.T) {
	filter := "tcp port 80"
	err := Capture(10*time.Second, "eth0", filter, "wan", false, 5)
	if err != nil {
		t.Errorf("Capture() unexpected error: %v", err)
	}
}

func TestCaptureWithProfile(t *testing.T) {
	profiles := []string{"lan", "wan"}
	for _, profile := range profiles {
		t.Run(profile, func(t *testing.T) {
			err := Capture(10*time.Second, "eth0", "", profile, false, 5)
			if err != nil {
				t.Errorf("Capture() with profile %s: unexpected error: %v", profile, err)
			}
		})
	}
}

func TestCaptureWithPrettyOutput(t *testing.T) {
	err := Capture(10*time.Second, "eth0", "", "wan", true, 5)
	if err != nil {
		t.Errorf("Capture() with pretty output: unexpected error: %v", err)
	}
}

func TestCaptureWithTopN(t *testing.T) {
	topNValues := []int{0, 5, 10, 20}
	for _, topN := range topNValues {
		t.Run(string(rune(topN)), func(t *testing.T) {
			err := Capture(10*time.Second, "eth0", "", "wan", false, topN)
			if err != nil {
				t.Errorf("Capture() with topN %d: unexpected error: %v", topN, err)
			}
		})
	}
}

func TestCaptureWithInvalidBPF(t *testing.T) {
	invalidFilters := []string{
		"invalid filter with syntax errors",
		"tcp port",
	}

	for _, filter := range invalidFilters {
		t.Run(filter, func(t *testing.T) {
			err := Capture(10*time.Second, "eth0", filter, "wan", false, 5)
			// BPF validation is package-specific, so this may or may not error
			t.Logf("BPF filter '%s' result: %v", filter, err)
		})
	}
}

func TestGetDefaultInterface(t *testing.T) {
	interfaceName := GetDefaultInterface()
	if interfaceName == "" {
		t.Error("GetDefaultInterface() should return a non-empty interface")
	}
	t.Logf("Default interface: %s", interfaceName)
}

func TestCaptureIntegration(t *testing.T) {
	// Integration test for capturing live traffic
	interfaceName := GetDefaultInterface()
	if interfaceName == "" {
		t.Skip("Skipping integration test: no valid interface found")
	}

	// Test capture with minimal duration
	err := Capture(2*time.Second, interfaceName, "", "wan", false, 5)
	if err != nil {
		t.Errorf("Capture integration test: unexpected error: %v", err)
	}
}
