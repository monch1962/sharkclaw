package main

import (
	"os"
	"time"

	cli "github.com/sharkclaw/sharkclaw/internal/cli"
	schema "github.com/sharkclaw/sharkclaw/internal/schema"
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

	startTime := time.Now()
	if cmd.Mode == "pcap" {
		cmd.SetPcapFile(cmd.PcapFile)
	}

	if cmd.Mode == "capture" {
		cmd.SetCaptureInterface(cmd.Interface)
		cmd.SetCaptureBPF(cmd.BPF)
	}

	runResult := schema.NewResult(
		schema.RunMode(cmd.Mode),
		cmd.Profile,
		startTime,
		startTime.Add(cmd.Duration),
		cmd.Duration.Seconds(),
	)
	runResult.SetVersion("1.0.0")

	if cmd.Mode == "pcap" {
		runResult.SetPcapFile(cmd.PcapFile)
	}

	if cmd.Mode == "capture" {
		runResult.SetCaptureInterface(cmd.Interface)
		runResult.SetCaptureBPF(cmd.BPF)
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
		output, err := runResult.PrettyString()
		if err != nil {
			os.Exit(1)
		}
		os.Stdout.WriteString(output)
		os.Exit(0)
	}

	output, err := runResult.String()
	if err != nil {
		os.Exit(1)
	}

	os.Stdout.WriteString(output)
	os.Exit(0)
}
