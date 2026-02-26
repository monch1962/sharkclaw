package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	analyze "github.com/sharkclaw/sharkclaw/internal/analyze"
	"github.com/sharkclaw/sharkclaw/internal/capture"
	cli "github.com/sharkclaw/sharkclaw/internal/cli"
	"github.com/sharkclaw/sharkclaw/internal/pcap"
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

	if cmd.Mode == "pcap" {
		if err := runPcapMode(cmd); err != nil {
			fmt.Fprintf(os.Stderr, "PCAP mode failed: %v\n", err)
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

	// Use "any" interface if none specified (like tcpdump)
	iface := cmd.Interface
	if iface == "" {
		iface = "any"
	}

	if duration > 0 {
		capturer, err := capture.NewCapturer(iface, cmd.BPF, 100*time.Millisecond)
		if err != nil {
			return fmt.Errorf("failed to create capturer: %w", err)
		}
		defer capturer.Close()

		capturePackets, err := capturer.Capture(duration)
		if err != nil {
			return fmt.Errorf("capture failed: %w", err)
		}
		packets = capture.Convert(capturePackets)
	} else {
		capturer, err := capture.NewCapturer(iface, cmd.BPF, 100*time.Millisecond)
		if err != nil {
			return fmt.Errorf("failed to create capturer: %w", err)
		}
		defer capturer.Close()

		capturePackets, err := capturer.Capture(5 * time.Second)
		if err != nil {
			return fmt.Errorf("capture failed: %w", err)
		}
		packets = capture.Convert(capturePackets)
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

	var jsonData []byte
	if cmd.Run.Verbose {
		// Include top_talkers when verbose
		jsonData, err = json.Marshal(result)
		if err != nil {
			return fmt.Errorf("failed to marshal result: %w", err)
		}
	} else {
		// Create a new result without top_talkers when not verbose
		verboseResult := map[string]interface{}{
			"run":     result.Run,
			"summary": result.Summary,
			"metrics": result.Metrics,
			"errors":  result.Errors,
		}
		jsonData, err = json.Marshal(verboseResult)
		if err != nil {
			return fmt.Errorf("failed to marshal result: %w", err)
		}
	}

	os.Stdout.WriteString(string(jsonData))
	return nil
}

func runPcapMode(cmd *cli.Command) error {
	startTime := time.Now()

	analyzer, err := analyze.NewAnalyzer(cmd.Profile, cmd.IncludeTopN)
	if err != nil {
		return fmt.Errorf("failed to create analyzer: %w", err)
	}

	reader, err := pcap.NewReader(cmd.PcapFile)
	if err != nil {
		return fmt.Errorf("failed to open PCAP file %s: %w", cmd.PcapFile, err)
	}

	packets := make([]analyze.Packet, 0)

	for {
		capturePackets, err := reader.Read()
		if err != nil {
			if err.Error() == "reader is closed or not initialized" {
				break
			}
			return fmt.Errorf("failed to read from PCAP file: %w", err)
		}

		for _, pkt := range capturePackets {
			packets = append(packets, analyze.Packet{
				Timestamp:       pkt.Timestamp,
				Length:          pkt.Length,
				SourceIP:        pkt.SourceIP,
				DestinationIP:   pkt.DestinationIP,
				SourcePort:      pkt.SourcePort,
				DestinationPort: pkt.DestinationPort,
				Protocol:        pkt.Protocol,
				SYN:             pkt.SYN,
				ACK:             pkt.ACK,
				RST:             pkt.RST,
			})
		}
	}

	endTime := time.Now()

	result, err := analyzer.AnalyzePcap(packets)
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	result.Run.StartTime = startTime
	result.Run.EndTime = endTime
	result.Run.Mode = "pcap"
	result.Run.DurationSeconds = float64(len(packets))

	jsonData, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	os.Stdout.WriteString(string(jsonData))
	return nil
}
