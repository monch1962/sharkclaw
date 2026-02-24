package main

import (
	"os"

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

	output, err := cmd.String()
	if err != nil {
		os.Exit(1)
	}

	os.Stdout.WriteString(output)
	os.Exit(0)
}
