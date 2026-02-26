package cli

import (
	"flag"
	"fmt"
	"strconv"
	"time"

	schema "github.com/sharkclaw/sharkclaw/internal/schema"
)

func ParseFlags(args []string) (*Command, error) {
	if len(args) == 0 {
		cmd := &Command{Run: &schema.Run{
			Mode:      schema.RunModeHelp,
			StartTime: time.Now(),
			EndTime:   time.Now(),
		}}
		cmd.initHelpFields()
		return cmd, nil
	}

	cmd := args[0]
	switch cmd {
	case "pcap":
		return parsePcapMode(args[1:])
	case "capture":
		return parseCaptureMode(args[1:])
	case "help", "--help", "-h":
		return parseHelpMode(), nil
	default:
		return nil, fmt.Errorf("unknown command: %s", cmd)
	}
}

func parsePcapMode(args []string) (*Command, error) {
	run := &schema.Run{
		Mode:      schema.RunModePCAP,
		Profile:   "wan",
		StartTime: time.Now(),
		EndTime:   time.Now(),
	}

	if len(args) == 0 {
		return nil, fmt.Errorf("pcap mode requires --file argument")
	}

	var f = flag.NewFlagSet("pcap", flag.ContinueOnError)
	f.StringVar(&run.Input.PcapFile, "file", "", "Path to PCAP/PCAPNG file")
	f.StringVar(&run.Capture.BPF, "filter", "", "BPF filter")
	f.StringVar(&run.Profile, "profile", "wan", "Threshold profile (lan|wan)")
	f.BoolVar(&run.Pretty, "pretty", false, "Output pretty-printed JSON")
	f.IntVar(&run.IncludeTopN, "include-topN", 5, "Limit top talkers to N entries (0 disables)")

	if err := f.Parse(args); err != nil {
		return nil, fmt.Errorf("failed to parse pcap flags: %w", err)
	}

	if run.Input.PcapFile == "" {
		return nil, fmt.Errorf("--file is required for pcap mode")
	}

	if run.Profile != "lan" && run.Profile != "wan" {
		return nil, fmt.Errorf("invalid profile: %s (must be lan or wan)", run.Profile)
	}

	if run.IncludeTopN < 0 {
		return nil, fmt.Errorf("--include-topN must be non-negative")
	}

	cmd := &Command{Run: run}
	cmd.SetPcapFile(run.Input.PcapFile)
	cmd.SetCaptureBPF(run.Capture.BPF)
	cmd.Flags = make(map[string]string)
	cmd.Flags["file"] = run.Input.PcapFile
	if run.Capture.BPF != "" {
		cmd.Flags["filter"] = run.Capture.BPF
	}
	if run.Profile != "wan" {
		cmd.Flags["profile"] = run.Profile
	}
	if run.Pretty {
		cmd.Flags["pretty"] = "true"
	}
	if run.IncludeTopN != 5 {
		cmd.Flags["include-topN"] = fmt.Sprintf("%d", run.IncludeTopN)
	}
	return cmd, nil
}

func parseCaptureMode(args []string) (*Command, error) {
	run := &schema.Run{
		Mode:      schema.RunModeCapture,
		StartTime: time.Now(),
		EndTime:   time.Now(),
	}

	var f = flag.NewFlagSet("capture", flag.ContinueOnError)

	var durationStr string
	f.StringVar(&durationStr, "duration", "10s", "Capture duration")

	var iface string
	var filter string
	var profile string
	var pretty bool
	var includeTopN int
	var verbose bool

	f.StringVar(&iface, "iface", "", "Network interface")
	f.StringVar(&filter, "filter", "", "BPF filter")
	f.StringVar(&profile, "profile", "wan", "Threshold profile (lan|wan)")
	f.BoolVar(&pretty, "pretty", false, "Output pretty-printed JSON")
	f.BoolVar(&verbose, "verbose", false, "Show top talkers in output")
	f.IntVar(&includeTopN, "include-topN", 5, "Limit top talkers to N entries (0 disables)")

	if err := f.Parse(args); err != nil {
		return nil, fmt.Errorf("failed to parse capture flags: %w", err)
	}

	// Parse duration manually to support both "10s" and "10"
	var err error
	run.Duration, err = time.ParseDuration(durationStr)
	if err != nil {
		seconds, err := strconv.Atoi(durationStr)
		if err != nil {
			return nil, fmt.Errorf("invalid duration format: %s", durationStr)
		}
		run.Duration = time.Duration(seconds) * time.Second
	}

	// Only set fields if they were explicitly provided
	run.Capture.Iface = iface
	run.Capture.BPF = filter
	run.Profile = profile
	run.Pretty = pretty
	run.IncludeTopN = includeTopN

	if run.Profile != "lan" && run.Profile != "wan" {
		return nil, fmt.Errorf("invalid profile: %s (must be lan or wan)", run.Profile)
	}

	if run.IncludeTopN < 0 {
		return nil, fmt.Errorf("--include-topN must be non-negative")
	}

	if run.Duration <= 0 {
		return nil, fmt.Errorf("--duration must be positive")
	}

	run.EndTime = run.StartTime.Add(run.Duration)
	run.Verbose = verbose

	cmd := &Command{Run: run}
	if iface != "" {
		cmd.SetCaptureInterface(iface)
	}
	if filter != "" {
		cmd.SetCaptureBPF(filter)
	}
	cmd.Flags = make(map[string]string)
	if run.Duration != 10*time.Second {
		cmd.Flags["duration"] = durationStr
	}
	if iface != "" {
		cmd.Flags["iface"] = iface
	}
	if filter != "" {
		cmd.Flags["filter"] = filter
	}
	if profile != "wan" {
		cmd.Flags["profile"] = profile
	}
	if pretty {
		cmd.Flags["pretty"] = "true"
	}
	if includeTopN != 5 {
		cmd.Flags["include-topN"] = fmt.Sprintf("%d", includeTopN)
	}
	return cmd, nil
}

func parseHelpMode() *Command {
	help := schema.NewHelp()
	cmd := &Command{Run: &schema.Run{
		Mode:      schema.RunModeHelp,
		StartTime: time.Now(),
		EndTime:   time.Now(),
		Help:      &help,
	}}
	cmd.initHelpFields()
	return cmd
}
