package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"strconv"
	"time"
)

type Command struct {
	Mode        string            `json:"mode"`
	PcapFile    string            `json:"pcap_file"`
	Interface   string            `json:"interface"`
	BPF         string            `json:"bpf"`
	Profile     string            `json:"profile"`
	Duration    time.Duration     `json:"duration"`
	Pretty      bool              `json:"pretty"`
	IncludeTopN int               `json:"include_topN"`
	Flags       map[string]string `json:"flags"`
	Description string            `json:"description"`
	Commands    []CommandInfo     `json:"commands"`
	Signals     []SignalInfo      `json:"signals"`
}

func (c *Command) SetPcapFile(file string) {
	c.PcapFile = file
}

func (c *Command) SetCaptureInterface(iface string) {
	c.Interface = iface
}

func (c *Command) SetCaptureBPF(bpf string) {
	c.BPF = bpf
}

type CommandInfo struct {
	Name        string   `json:"name"`
	Examples    []string `json:"examples"`
	Description string   `json:"description"`
}

type SignalInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Meaning     string `json:"meaning"`
}

func ParseFlags(args []string) (*Command, error) {
	if len(args) == 0 {
		return &Command{
			Mode:        "help",
			Description: "sharkclaw detects and counts 'weird' network behaviors",
		}, nil
	}

	cmd := args[0]
	var result *Command
	var err error

	switch cmd {
	case "pcap":
		result, err = parsePcapMode(args[1:])
	case "capture":
		result, err = parseCaptureMode(args[1:])
	case "help", "--help", "-h":
		return parseHelpMode(), nil
	default:
		return nil, fmt.Errorf("unknown command: %s", cmd)
	}

	if err != nil {
		return nil, err
	}

	return result, nil
}

func parsePcapMode(args []string) (*Command, error) {
	cmd := &Command{
		Mode:    "pcap",
		Profile: "wan",
		Flags:   make(map[string]string),
	}

	if len(args) == 0 {
		return nil, fmt.Errorf("pcap mode requires --file argument")
	}

	var f = flag.NewFlagSet("pcap", flag.ContinueOnError)
	f.StringVar(&cmd.PcapFile, "file", "", "Path to PCAP/PCAPNG file")
	f.StringVar(&cmd.BPF, "filter", "", "BPF filter")
	f.StringVar(&cmd.Profile, "profile", "wan", "Threshold profile (lan|wan)")
	f.BoolVar(&cmd.Pretty, "pretty", false, "Output pretty-printed JSON")
	f.IntVar(&cmd.IncludeTopN, "include-topN", 5, "Limit top talkers to N entries (0 disables)")

	if err := f.Parse(args); err != nil {
		return nil, fmt.Errorf("failed to parse pcap flags: %w", err)
	}

	if cmd.PcapFile == "" {
		return nil, fmt.Errorf("--file is required for pcap mode")
	}

	if cmd.Profile != "lan" && cmd.Profile != "wan" {
		return nil, fmt.Errorf("invalid profile: %s (must be lan or wan)", cmd.Profile)
	}

	if cmd.IncludeTopN < 0 {
		return nil, fmt.Errorf("--include-topN must be non-negative")
	}

	cmd.Flags["file"] = cmd.PcapFile
	cmd.Flags["profile"] = cmd.Profile
	cmd.Flags["filter"] = cmd.BPF
	cmd.Flags["pretty"] = fmt.Sprintf("%v", cmd.Pretty)
	cmd.Flags["include-topN"] = strconv.Itoa(cmd.IncludeTopN)

	return cmd, nil
}

func parseCaptureMode(args []string) (*Command, error) {
	cmd := &Command{
		Mode:        "capture",
		Interface:   "",
		BPF:         "",
		Profile:     "wan",
		IncludeTopN: 5,
		Flags:       make(map[string]string),
	}

	var f = flag.NewFlagSet("capture", flag.ContinueOnError)

	// Use string flag for duration to handle both "10s" and "10"
	var durationStr string
	f.StringVar(&durationStr, "duration", "10s", "Capture duration")

	var iface string
	var filter string
	var profile string
	var pretty bool
	var includeTopN int

	f.StringVar(&iface, "iface", "", "Network interface")
	f.StringVar(&filter, "filter", "", "BPF filter")
	f.StringVar(&profile, "profile", "wan", "Threshold profile (lan|wan)")
	f.BoolVar(&pretty, "pretty", false, "Output pretty-printed JSON")
	f.IntVar(&includeTopN, "include-topN", 5, "Limit top talkers to N entries (0 disables)")

	if err := f.Parse(args); err != nil {
		return nil, fmt.Errorf("failed to parse capture flags: %w", err)
	}

	// Parse duration manually to support both "10s" and "10"
	var err error
	cmd.Duration, err = time.ParseDuration(durationStr)
	if err != nil {
		// Try to parse as integer seconds
		seconds, err := strconv.Atoi(durationStr)
		if err != nil {
			return nil, fmt.Errorf("invalid duration format: %s", durationStr)
		}
		cmd.Duration = time.Duration(seconds) * time.Second
	}

	// Only set fields if they were explicitly provided
	cmd.Interface = iface
	cmd.BPF = filter
	cmd.Profile = profile
	cmd.Pretty = pretty
	cmd.IncludeTopN = includeTopN

	if cmd.Profile != "lan" && cmd.Profile != "wan" {
		return nil, fmt.Errorf("invalid profile: %s (must be lan or wan)", cmd.Profile)
	}

	if cmd.IncludeTopN < 0 {
		return nil, fmt.Errorf("--include-topN must be non-negative")
	}

	if cmd.Duration <= 0 {
		return nil, fmt.Errorf("--duration must be positive")
	}

	cmd.Flags["duration"] = durationStr
	if cmd.Interface != "" {
		cmd.Flags["iface"] = cmd.Interface
	}
	if cmd.BPF != "" {
		cmd.Flags["filter"] = cmd.BPF
	}
	cmd.Flags["profile"] = cmd.Profile
	cmd.Flags["pretty"] = fmt.Sprintf("%v", cmd.Pretty)
	cmd.Flags["include-topN"] = strconv.Itoa(cmd.IncludeTopN)

	return cmd, nil
}

func parseHelpMode() *Command {
	return &Command{
		Mode:        "help",
		Description: "Detects and counts 'weird' network behaviors indicative of attacks and/or network problems",
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
		Flags: map[string]string{
			"--file":         "Path to PCAP/PCAPNG file (PCAP mode only)",
			"--duration":     "Capture duration (e.g., 10s, 30s, 5m). PCAP mode: use file instead.",
			"--iface":        "Network interface for capture (capture mode only)",
			"--filter":       "BPF filter for packet capture (e.g., 'tcp port 80')",
			"--profile":      "Threshold profile (affects high-latency thresholds and DNS timeouts)",
			"--pretty":       "Output pretty-printed JSON",
			"--include-topN": "Limit top talkers arrays to N entries (0 disables)",
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

type FlagInfo struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Default     string `json:"default"`
	Description string `json:"description"`
}

func (c *Command) ValidateFlags() error {
	switch c.Mode {
	case "pcap":
		if c.PcapFile == "" {
			return fmt.Errorf("--file is required for pcap mode")
		}
		if c.Profile != "lan" && c.Profile != "wan" {
			return fmt.Errorf("invalid profile: %s (must be lan or wan)", c.Profile)
		}
	case "capture":
		if c.Duration <= 0 {
			return fmt.Errorf("--duration must be positive")
		}
		if c.Profile != "lan" && c.Profile != "wan" {
			return fmt.Errorf("invalid profile: %s (must be lan or wan)", c.Profile)
		}
	}
	return nil
}

func (c *Command) String() (string, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("failed to marshal command to JSON: %w", err)
	}
	return string(data), nil
}

func (c *Command) PrettyString() (string, error) {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal command to JSON: %w", err)
	}
	return string(data), nil
}

func GetDefaultInterface() string {
	return "any"
}

func SetVersion(version string) {
	// In a real implementation, this would set the version in the schema
	// For now, this is a placeholder
}
