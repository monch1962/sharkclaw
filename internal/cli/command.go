package cli

import (
	"encoding/json"
	"fmt"

	schema "github.com/sharkclaw/sharkclaw/internal/schema"
)

type Command struct {
	*schema.Run

	// Exposed fields for backward compatibility
	Flags       map[string]string `json:"flags"`
	Commands    []string          `json:"commands"`
	Description string            `json:"description"`
	Signals     []string          `json:"signals"`

	// Exposed fields for backward compatibility
	PcapFile  string `json:"pcap_file"`
	Interface string `json:"interface"`
	BPF       string `json:"bpf"`
}

func (c *Command) SetPcapFile(file string) {
	c.Run.Input.PcapFile = file
	c.PcapFile = file
}

func (c *Command) SetCaptureInterface(iface string) {
	c.Run.Capture.Iface = iface
	c.Interface = iface
}

func (c *Command) SetCaptureBPF(bpf string) {
	c.Run.Capture.BPF = bpf
	c.BPF = bpf
}

func NewCommandFromRun(run *schema.Run) *Command {
	return &Command{Run: run}
}

func (c *Command) PrettyString() (string, error) {
	if c.Run.Mode == schema.RunModeHelp && c.Run.Help != nil {
		return c.generateSimpleHelp()
	}
	return c.Run.PrettyString()
}

func (c *Command) generateSimpleHelp() (string, error) {
	help := c.Run.Help
	result := fmt.Sprintf("sharkclaw - Detects and counts 'weird' network behaviors indicative of attacks and/or network problems.\n\n")

	result += fmt.Sprintf("Commands:\n")
	for _, cmd := range help.Commands {
		result += fmt.Sprintf("  %s: %s\n", cmd.Name, cmd.Description)
		if len(cmd.Examples) > 0 {
			for _, example := range cmd.Examples {
				result += fmt.Sprintf("    %s\n", example)
			}
		}
	}

	result += fmt.Sprintf("\nGlobal Flags:\n")
	for _, flag := range help.Flags {
		result += fmt.Sprintf("  %s (%s): %s\n", flag.Name, flag.Type, flag.Description)
		if flag.Default != "" {
			result += fmt.Sprintf("    Default: %s\n", flag.Default)
		}
	}

	result += fmt.Sprintf("\nSupported Signals:\n")
	for _, signal := range help.Signals {
		result += fmt.Sprintf("  %s: %s - %s\n", signal.Name, signal.Description, signal.Meaning)
	}

	return result, nil
}

func (c *Command) String() (string, error) {
	return c.Run.String()
}

func (c *Command) ValidateFlags() error {
	switch c.Run.Mode {
	case schema.RunModePCAP:
		if c.Run.Input.PcapFile == "" {
			return fmt.Errorf("pcap file is required for pcap mode")
		}
		if c.Run.Profile != "" && c.Run.Profile != "lan" && c.Run.Profile != "wan" {
			return fmt.Errorf("invalid profile: %s. Valid profiles are lan and wan", c.Run.Profile)
		}
	case schema.RunModeCapture:
		if c.Run.Duration == 0 {
			return fmt.Errorf("duration is required for capture mode")
		}
		if c.Run.Capture.Iface == "" {
			return fmt.Errorf("interface is required for capture mode")
		}
	case schema.RunModeHelp:
		// Help mode is always valid
		return nil
	default:
		return fmt.Errorf("invalid mode: %s", c.Run.Mode)
	}
	return nil
}

func getHelpFields() (flags []string, commands []string, description string, signals []string) {
	flags = []string{
		"--file",
		"--duration",
		"--iface",
		"--filter",
		"--profile",
		"--pretty",
		"--include-topN",
	}
	commands = []string{"pcap", "capture", "help"}
	description = "sharkclaw is a CLI tool for detecting weird network behaviors"
	signals = []string{"SIGINT", "SIGTERM", "SIGQUIT"}
	return
}

func (c *Command) initHelpFields() {
	if c.Run.Mode == schema.RunModeHelp && c.Run.Help != nil {
		c.Flags = make(map[string]string)
		for _, f := range c.Run.Help.Flags {
			c.Flags[f.Name] = f.Type
		}
		c.Commands = make([]string, len(c.Run.Help.Commands))
		for i, cmd := range c.Run.Help.Commands {
			c.Commands[i] = cmd.Name
		}
		c.Description = c.Run.Help.Description
		c.Signals = make([]string, len(c.Run.Help.Signals))
		for i, sig := range c.Run.Help.Signals {
			c.Signals[i] = sig.Name
		}
	} else {
		flags, commands, description, signals := getHelpFields()
		c.Flags = make(map[string]string)
		for _, f := range flags {
			c.Flags[f] = "string"
		}
		c.Commands = commands
		c.Description = description
		c.Signals = signals
	}
}

func (c *Command) MarshalJSON() ([]byte, error) {
	type Alias Command
	flags := make([]string, 0, len(c.Flags))
	for k := range c.Flags {
		flags = append(flags, k)
	}
	return json.Marshal(&struct {
		*Alias
		Flags       []string `json:"flags"`
		Commands    []string `json:"commands"`
		Description string   `json:"description"`
		Signals     []string `json:"signals"`
	}{
		Alias:       (*Alias)(c),
		Flags:       flags,
		Commands:    c.Commands,
		Description: c.Description,
		Signals:     c.Signals,
	})
}

func (c *Command) ModeString() string {
	return string(c.Run.Mode)
}
