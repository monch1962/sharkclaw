package cli

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

type testCase struct {
	name            string
	args            []string
	expectedMode    string
	expectedProfile string
	expectError     bool
	duration        time.Duration
	iface           string
	filter          string
	profile         string
	includeTopN     int
	pretty          bool
}

func TestCLIFlags(t *testing.T) {
	testCases := []testCase{
		{
			name:            "pcap mode with file",
			args:            []string{"pcap", "--file", "test.pcap"},
			expectedMode:    "pcap",
			expectedProfile: "wan",
			expectError:     false,
		},
		{
			name:            "pcap mode with profile lan",
			args:            []string{"pcap", "--file", "test.pcap", "--profile", "lan"},
			expectedMode:    "pcap",
			expectedProfile: "lan",
			expectError:     false,
		},
		{
			name:            "pcap mode with topN",
			args:            []string{"pcap", "--file", "test.pcap", "--include-topN", "10"},
			expectedMode:    "pcap",
			expectedProfile: "wan",
			expectError:     false,
		},
		{
			name:            "pcap mode with pretty output",
			args:            []string{"pcap", "--file", "test.pcap", "--pretty"},
			expectedMode:    "pcap",
			expectedProfile: "wan",
			expectError:     false,
		},
		{
			name:            "capture mode with duration",
			args:            []string{"capture", "--duration", "10s"},
			expectedMode:    "capture",
			expectedProfile: "wan",
			expectError:     false,
		},
		{
			name:            "capture mode with duration in seconds",
			args:            []string{"capture", "--duration", "10"},
			expectedMode:    "capture",
			expectedProfile: "wan",
			expectError:     false,
		},
		{
			name:            "capture mode with profile",
			args:            []string{"capture", "--duration", "10s", "--profile", "lan"},
			expectedMode:    "capture",
			expectedProfile: "lan",
			expectError:     false,
		},
		{
			name:            "capture mode with filter",
			args:            []string{"capture", "--duration", "10s", "--filter", "tcp port 80"},
			expectedMode:    "capture",
			expectedProfile: "wan",
			expectError:     false,
		},
		{
			name:            "capture mode with interface",
			args:            []string{"capture", "--duration", "10s", "--iface", "eth0"},
			expectedMode:    "capture",
			expectedProfile: "wan",
			expectError:     false,
		},
		{
			name:            "capture mode with all flags",
			args:            []string{"capture", "--duration", "10s", "--iface", "eth0", "--filter", "tcp port 80", "--profile", "lan", "--pretty", "--include-topN", "20"},
			expectedMode:    "capture",
			expectedProfile: "lan",
			expectError:     false,
		},
		{
			name:            "capture mode invalid duration",
			args:            []string{"capture", "--duration", "invalid"},
			expectedMode:    "",
			expectedProfile: "",
			expectError:     true,
		},
		{
			name:            "capture mode negative duration",
			args:            []string{"capture", "--duration", "-10s"},
			expectedMode:    "",
			expectedProfile: "",
			expectError:     true,
		},
		{
			name:            "pcap mode missing file",
			args:            []string{"pcap"},
			expectedMode:    "pcap",
			expectedProfile: "",
			expectError:     true,
		},
		{
			name:            "pcap mode invalid profile",
			args:            []string{"pcap", "--file", "test.pcap", "--profile", "invalid"},
			expectedMode:    "",
			expectedProfile: "",
			expectError:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			oldArgs := os.Args
			os.Args = []string{"sharkclaw"}
			os.Args = append(os.Args, tc.args...)

			defer func() {
				os.Args = oldArgs
			}()

			cmd, err := ParseFlags(os.Args[1:])
			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if cmd.Mode != tc.expectedMode {
				t.Errorf("Mode mismatch: got %s, want %s", cmd.Mode, tc.expectedMode)
			}

			if cmd.Profile != tc.expectedProfile {
				t.Errorf("Profile mismatch: got %s, want %s", cmd.Profile, tc.expectedProfile)
			}
		})
	}
}

func TestHelpCommand(t *testing.T) {
	testCases := []testCase{
		{
			name:         "help command",
			args:         []string{"help"},
			expectedMode: "help",
			expectError:  false,
		},
		{
			name:         "help with --help",
			args:         []string{"--help"},
			expectedMode: "help",
			expectError:  false,
		},
		{
			name:         "help with -h",
			args:         []string{"-h"},
			expectedMode: "help",
			expectError:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			oldArgs := os.Args
			os.Args = []string{"sharkclaw"}
			os.Args = append(os.Args, tc.args...)

			defer func() {
				os.Args = oldArgs
			}()

			cmd, err := ParseFlags(os.Args[1:])
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if cmd.Mode != tc.expectedMode {
				t.Errorf("Mode mismatch: got %s, want %s", cmd.Mode, tc.expectedMode)
			}

			if cmd.Mode != "help" {
				return
			}

			if cmd.Flags == nil {
				t.Error("Flags should not be nil for help command")
			}

			if cmd.Description == "" {
				t.Error("Description should not be empty for help command")
			}
		})
	}
}

func TestPcapMode(t *testing.T) {
	testCases := []testCase{
		{
			name:         "pcap with file only",
			args:         []string{"pcap", "--file", "test.pcap"},
			expectedMode: "pcap",
			expectError:  false,
		},
		{
			name:         "pcap with file and filter",
			args:         []string{"pcap", "--file", "test.pcap", "--filter", "tcp port 80"},
			expectedMode: "pcap",
			expectError:  false,
		},
		{
			name:         "pcap with file and profile",
			args:         []string{"pcap", "--file", "test.pcap", "--profile", "wan"},
			expectedMode: "pcap",
			expectError:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			oldArgs := os.Args
			os.Args = []string{"sharkclaw"}
			os.Args = append(os.Args, tc.args...)

			defer func() {
				os.Args = oldArgs
			}()

			cmd, err := ParseFlags(os.Args[1:])
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if cmd.Mode != tc.expectedMode {
				t.Errorf("Mode mismatch: got %s, want %s", cmd.Mode, tc.expectedMode)
			}

			if cmd.Mode != "pcap" {
				return
			}

			if cmd.PcapFile != "test.pcap" {
				t.Errorf("PcapFile mismatch: got %s, want test.pcap", cmd.PcapFile)
			}

			if cmd.Flags["file"] != "test.pcap" {
				t.Errorf("Flags[file] mismatch: got %s, want test.pcap", cmd.Flags["file"])
			}
		})
	}
}

func TestCaptureMode(t *testing.T) {
	testCases := []testCase{
		{
			name:         "capture with duration only",
			args:         []string{"capture", "--duration", "10s"},
			expectedMode: "capture",
			expectError:  false,
			duration:     10 * time.Second,
		},
		{
			name:         "capture with interface only",
			args:         []string{"capture", "--iface", "eth0"},
			expectedMode: "capture",
			expectError:  false,
			iface:        "eth0",
		},
		{
			name:         "capture with all options",
			args:         []string{"capture", "--duration", "10s", "--iface", "eth0", "--filter", "tcp port 80", "--profile", "lan", "--pretty", "--include-topN", "15"},
			expectedMode: "capture",
			expectError:  false,
			duration:     10 * time.Second,
			iface:        "eth0",
			filter:       "tcp port 80",
			profile:      "lan",
			includeTopN:  15,
			pretty:       true,
		},
		{
			name:         "capture with filter only",
			args:         []string{"capture", "--filter", "tcp port 80"},
			expectedMode: "capture",
			expectError:  false,
			filter:       "tcp port 80",
		},
		{
			name:         "capture with profile lan",
			args:         []string{"capture", "--profile", "lan"},
			expectedMode: "capture",
			expectError:  false,
			profile:      "lan",
		},
		{
			name:         "capture with pretty",
			args:         []string{"capture", "--pretty"},
			expectedMode: "capture",
			expectError:  false,
			pretty:       true,
		},
		{
			name:         "capture with includeTopN",
			args:         []string{"capture", "--include-topN", "10"},
			expectedMode: "capture",
			expectError:  false,
			includeTopN:  10,
		},
		{
			name:         "capture with multiple flags",
			args:         []string{"capture", "--duration", "15s", "--profile", "lan", "--pretty"},
			expectedMode: "capture",
			expectError:  false,
			duration:     15 * time.Second,
			profile:      "lan",
			pretty:       true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			oldArgs := os.Args
			os.Args = []string{"sharkclaw"}
			os.Args = append(os.Args, tc.args...)

			defer func() {
				os.Args = oldArgs
			}()

			cmd, err := ParseFlags(os.Args[1:])
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if cmd.Mode != tc.expectedMode {
				t.Errorf("Mode mismatch: got %s, want %s", cmd.Mode, tc.expectedMode)
			}

			if cmd.Mode != "capture" {
				return
			}

			if tc.duration > 0 && cmd.Duration != tc.duration {
				t.Errorf("Duration mismatch: got %v, want %v", cmd.Duration, tc.duration)
			}

			if tc.iface != "" && cmd.Interface != tc.iface {
				t.Errorf("Interface mismatch: got %s, want %s", cmd.Interface, tc.iface)
			}

			if tc.filter != "" && cmd.BPF != tc.filter {
				t.Errorf("BPF mismatch: got %s, want %s", cmd.BPF, tc.filter)
			}

			if tc.profile != "" && cmd.Profile != tc.profile {
				t.Errorf("Profile mismatch: got %s, want %s", cmd.Profile, tc.profile)
			}

			if tc.includeTopN > 0 && cmd.IncludeTopN != tc.includeTopN {
				t.Errorf("IncludeTopN mismatch: got %d, want %d", cmd.IncludeTopN, tc.includeTopN)
			}

			if tc.pretty && !cmd.Pretty {
				t.Errorf("Pretty mismatch: got %v, want %v", cmd.Pretty, tc.pretty)
			}
		})
	}
}

func TestInvalidCommands(t *testing.T) {
	invalidCommands := []string{"invalid", "unknown", "random"}

	for _, cmd := range invalidCommands {
		t.Run(cmd, func(t *testing.T) {
			oldArgs := os.Args
			os.Args = []string{"sharkclaw", cmd}

			defer func() {
				os.Args = oldArgs
			}()

			_, err := ParseFlags(os.Args[1:])
			if err == nil {
				t.Errorf("Expected error for invalid command %s, got none", cmd)
			}
		})
	}
}

func TestFlagDefaults(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"sharkclaw", "capture", "--duration", "10s"}

	defer func() {
		os.Args = oldArgs
	}()

	cmd, err := ParseFlags(os.Args[1:])
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if cmd.Duration != 10*time.Second {
		t.Errorf("Default duration should be 10s, got %v", cmd.Duration)
	}

	if cmd.Profile != "wan" {
		t.Errorf("Default profile should be wan, got %s", cmd.Profile)
	}

	if cmd.IncludeTopN != 5 {
		t.Errorf("Default include-topN should be 5, got %d", cmd.IncludeTopN)
	}

	if cmd.Pretty {
		t.Error("Default pretty should be false")
	}

	if cmd.BPF != "" {
		t.Errorf("BPF should be empty by default, got %s", cmd.BPF)
	}
}

func TestModeValidation(t *testing.T) {
	validModes := map[string]bool{
		"pcap":    true,
		"capture": true,
		"help":    true,
	}

	for mode := range validModes {
		oldArgs := os.Args
		os.Args = []string{"sharkclaw", mode}

		defer func() {
			os.Args = oldArgs
		}()

		cmd, err := ParseFlags(os.Args[1:])
		if err != nil {
			t.Errorf("Error for valid mode %s: %v", mode, err)
			return
		}

		if cmd == nil {
			t.Errorf("Command should not be nil for mode %s", mode)
			return
		}

		if cmd.Mode != mode {
			t.Errorf("Mode should be %s, got %s", mode, cmd.Mode)
		}
	}
}

func TestParseFlagsString(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"sharkclaw", "pcap", "--file", "test.pcap", "--pretty", "--include-topN", "3"}

	defer func() {
		os.Args = oldArgs
	}()

	cmd, err := ParseFlags(os.Args[1:])
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	output, err := cmd.String()
	if err != nil {
		t.Fatalf("Failed to get string representation: %v", err)
	}

	var parsedCmd Command
	if err := json.Unmarshal([]byte(output), &parsedCmd); err != nil {
		t.Fatalf("Failed to parse string output: %v", err)
	}

	if parsedCmd.Mode != cmd.Mode {
		t.Errorf("Mode mismatch in string representation")
	}

	if parsedCmd.PcapFile != cmd.PcapFile {
		t.Errorf("PcapFile mismatch in string representation")
	}

	if parsedCmd.Pretty != cmd.Pretty {
		t.Errorf("Pretty mismatch in string representation")
	}
}

func TestValidateFlags(t *testing.T) {
	testCases := []struct {
		name      string
		cmd       Command
		expectErr bool
	}{
		{
			name: "valid pcap mode",
			cmd: Command{
				Mode:     "pcap",
				PcapFile: "test.pcap",
			},
			expectErr: false,
		},
		{
			name: "invalid mode",
			cmd: Command{
				Mode: "invalid",
			},
			expectErr: true,
		},
		{
			name: "capture mode without interface on non-linux",
			cmd: Command{
				Mode:      "capture",
				Interface: "",
			},
			expectErr: true,
		},
		{
			name: "pcap mode with valid profile",
			cmd: Command{
				Mode:        "pcap",
				Profile:     "wan",
				PcapFile:    "test.pcap",
				IncludeTopN: 5,
			},
			expectErr: false,
		},
		{
			name: "pcap mode with invalid profile",
			cmd: Command{
				Mode:        "pcap",
				Profile:     "invalid",
				PcapFile:    "test.pcap",
				IncludeTopN: 5,
			},
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cmd.ValidateFlags()
			if tc.expectErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestCommandExamples(t *testing.T) {
	captureExamples := []string{
		"sharkclaw capture --duration 10s",
		"sharkclaw capture --duration 30s --profile lan",
		"sharkclaw capture --iface eth0 --duration 15s",
	}

	for _, example := range captureExamples {
		t.Run(example, func(t *testing.T) {
			args := strings.Split(example, " ")
			// Remove the "sharkclaw" prefix from args
			args = args[1:]
			oldArgs := os.Args
			os.Args = []string{"sharkclaw"}
			os.Args = append(os.Args, args...)

			defer func() {
				os.Args = oldArgs
			}()

			_, err := ParseFlags(os.Args[1:])
			if err != nil {
				t.Errorf("Failed to parse example: %v", err)
			}
		})
	}
}

func TestHelpJSONSchema(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"sharkclaw", "help"}

	defer func() {
		os.Args = oldArgs
	}()

	cmd, err := ParseFlags(os.Args[1:])
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if cmd.Mode != "help" {
		t.Error("Should be help mode")
	}

	if cmd.Description == "" {
		t.Error("Help description should not be empty")
	}

	if len(cmd.Commands) == 0 {
		t.Error("Help should have commands")
	}

	if len(cmd.Flags) == 0 {
		t.Error("Help should have flags")
	}

	if len(cmd.Signals) == 0 {
		t.Error("Help should have signals")
	}

	expectedCommands := []string{"pcap", "capture", "help"}
	for _, expectedCmd := range expectedCommands {
		found := false
		for _, cmd := range cmd.Commands {
			if cmd.Name == expectedCmd {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Missing command %s in help", expectedCmd)
		}
	}

	expectedFlags := []string{
		"--file", "--duration", "--iface", "--filter",
		"--profile", "--pretty", "--include-topN",
	}

	for _, expectedFlag := range expectedFlags {
		found := false
		for key := range cmd.Flags {
			if key == expectedFlag {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Missing flag %s in help", expectedFlag)
		}
	}
}

func TestAllRequiredFieldsPresent(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"sharkclaw", "pcap", "--file", "test.pcap"}

	defer func() {
		os.Args = oldArgs
	}()

	cmd, err := ParseFlags(os.Args[1:])
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	requiredFields := []string{"Mode", "PcapFile", "Profile", "Pretty", "IncludeTopN", "Interface", "Filter"}

	for _, field := range requiredFields {
		switch field {
		case "Mode":
			if cmd.Mode == "" {
				t.Error("Mode should not be empty")
			}
		case "PcapFile":
			if cmd.PcapFile == "" {
				t.Error("PcapFile should not be empty for pcap mode")
			}
		case "Profile":
			if cmd.Profile == "" {
				t.Error("Profile should not be empty")
			}
		case "Pretty":
			if cmd.Pretty {
				t.Error("Pretty should be false by default")
			}
		case "IncludeTopN":
			if cmd.IncludeTopN != 5 {
				t.Errorf("IncludeTopN should be 5 by default, got %d", cmd.IncludeTopN)
			}
		case "Interface":
			if cmd.Interface != "" {
				t.Error("Interface should be empty by default")
			}
		case "Filter":
			if cmd.BPF != "" {
				t.Error("Filter should be empty by default")
			}
		}
	}
}

func TestInterfaceDefault(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"sharkclaw", "capture", "--duration", "10s"}

	defer func() {
		os.Args = oldArgs
	}()

	cmd, err := ParseFlags(os.Args[1:])
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if cmd.Interface != "" {
		t.Errorf("Interface should be empty by default, got %s", cmd.Interface)
	}
}

func TestPrettyFlag(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"sharkclaw", "pcap", "--file", "test.pcap", "--pretty"}

	defer func() {
		os.Args = oldArgs
	}()

	cmd, err := ParseFlags(os.Args[1:])
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !cmd.Pretty {
		t.Error("Pretty should be true when set")
	}

	str, err := cmd.String()
	if err != nil || str == "" {
		t.Error("String output should not be empty")
	}
}

func TestIncludeTopNValidation(t *testing.T) {
	testCases := []struct {
		name      string
		topN      string
		expectErr bool
	}{
		{
			name:      "valid topN",
			topN:      "10",
			expectErr: false,
		},
		{
			name:      "zero topN",
			topN:      "0",
			expectErr: false,
		},
		{
			name:      "negative topN",
			topN:      "-1",
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			oldArgs := os.Args
			os.Args = []string{"sharkclaw", "pcap", "--file", "test.pcap", "--include-topN", tc.topN}

			defer func() {
				os.Args = oldArgs
			}()

			cmd, err := ParseFlags(os.Args[1:])
			if tc.expectErr {
				if err == nil {
					t.Error("Expected error for invalid topN")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if tc.topN == "0" && cmd.IncludeTopN != 0 {
				t.Errorf("IncludeTopN should be 0 for 0, got %d", cmd.IncludeTopN)
			}
		})
	}
}
