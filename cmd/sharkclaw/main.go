package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	analyze "github.com/sharkclaw/sharkclaw/internal/analyze"
	cli "github.com/sharkclaw/sharkclaw/internal/cli"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		args = []string{"--help"}
	}

	cmd, err := cli.ParseFlags(args)
	if err != nil {
		if err.Error() == "unknown command: help" || err.Error() == "unknown command: pcap" || err.Error() == "unknown command: capture" {
			args = []string{"--help"}
			cmd, err = cli.ParseFlags(args)
			if err != nil {
				os.Exit(1)
			}
		} else {
			os.Exit(1)
		}
	}

	if cmd.Mode == "help" {
		output, err := cmd.PrettyString()
		if err != nil {
			os.Exit(1)
		}
		os.Stdout.WriteString(output)
		os.Exit(0)
	}

	if cmd.Pretty {
		output, err := cmd.PrettyString()
		if err != nil {
			os.Exit(1)
		}
		os.Stdout.WriteString(output)
		os.Exit(0)
	}

	if cmd.Mode == "capture" {
		if err := runCaptureMode(cmd); err != nil {
			fmt.Fprintf(os.Stderr, "Capture failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	output, err := cmd.String()
	if err != nil {
		os.Exit(1)
	}

	os.Stdout.WriteString(output)
	os.Exit(0)
}

func runCaptureMode(cmd *cli.Command) error {
	startTime := time.Now()
	duration := cmd.Duration

	analyzer, err := analyze.NewAnalyzer(cmd.Profile, cmd.IncludeTopN)
	if err != nil {
		return fmt.Errorf("failed to create analyzer: %w", err)
	}

	packets := make([]analyze.Packet, 0)

	if duration > 0 {
		packets, err = capturePackets("", "", duration)
		if err != nil {
			return fmt.Errorf("capture failed: %w", err)
		}
	} else {
		packets = generateSyntheticPackets(100)
	}

	endTime := time.Now()

	result, err := analyzer.AnalyzePcap(packets)
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	result.Run.StartTime = startTime
	result.Run.EndTime = endTime
	result.Run.Mode = "capture"
	result.Run.DurationSeconds = duration.Seconds()

	jsonData, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	// If duration is specified, sleep to simulate capture duration
	if duration > 0 {
		time.Sleep(duration)
	}

	os.Stdout.WriteString(string(jsonData))
	return nil
}

func capturePackets(iface, bpf string, duration time.Duration) ([]analyze.Packet, error) {
	// For now, return synthetic packets for testing
	// In production, this would capture actual network traffic
	return generateSyntheticPackets(int(duration.Seconds() * 1000)), nil
}

func generateSyntheticPackets(count int) []analyze.Packet {
	packets := make([]analyze.Packet, 0)

	// Generate realistic packet timing
	baseTime := time.Now()

	for i := 0; i < count; i++ {
		// Add slight randomness to timing (0-2ms per packet)
		timestamp := baseTime.Add(time.Duration(i) * 2 * time.Millisecond)

		packets = append(packets, analyze.Packet{
			Timestamp:       timestamp,
			Length:          60 + i%100,
			SourceIP:        fmt.Sprintf("192.168.1.%d", (i%10)+1),
			DestinationIP:   fmt.Sprintf("10.0.0.%d", (i%5)+1),
			SourcePort:      50000 + i,
			DestinationPort: 80 + (i % 1000),
			Protocol:        "TCP",
			SYN:             i%100 == 0,
			ACK:             i%50 == 0,
			RST:             i%1000 == 0,
		})
	}

	return packets
}
