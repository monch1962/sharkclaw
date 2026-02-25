package capture

import (
	"errors"
	"fmt"
	"time"
)

var ErrInvalidDuration = errors.New("duration must be positive")
var ErrNoInterface = errors.New("network interface is required for capture mode")
var ErrInvalidBPF = errors.New("invalid BPF filter syntax")

// Capture starts live traffic capture for a specified duration and performs analysis
func Capture(duration time.Duration, iface string, bpf string, profile string, pretty bool, includeTopN int) error {
	// Validate duration
	if duration <= 0 {
		return ErrInvalidDuration
	}

	// Validate interface
	if iface == "" {
		return ErrNoInterface
	}

	// Validate BPF filter (basic syntax check)
	if bpf != "" {
		if len(bpf) < 5 {
			return ErrInvalidBPF
		}
	}

	// Validate profile
	validProfiles := map[string]bool{
		"lan":  true,
		"wan":  true,
		"help": true,
	}
	if !validProfiles[profile] {
		return fmt.Errorf("invalid profile: %s (must be lan, wan, or help)", profile)
	}

	// Validate includeTopN
	if includeTopN < 0 {
		return fmt.Errorf("includeTopN must be non-negative")
	}

	// TODO: Implement actual live capture using gopacket
	// This is a placeholder for the actual implementation

	return nil
}

// GetDefaultInterface returns the default network interface for capture
func GetDefaultInterface() string {
	// TODO: Implement default interface detection
	// On Linux, this would typically be "any" or detect from system
	// For now, return a placeholder
	return "any"
}

// StartCapture starts the capture in the background
func StartCapture(duration time.Duration, iface string, bpf string) (chan Packet, error) {
	// Validate inputs
	if duration <= 0 {
		return nil, ErrInvalidDuration
	}

	if iface == "" {
		return nil, ErrNoInterface
	}

	// TODO: Implement actual capture using gopacket
	// This is a placeholder for the actual implementation

	packets := make(chan Packet, 1000)
	close(packets)

	return packets, nil
}

// StopCapture stops the active capture
func StopCapture() error {
	// TODO: Implement capture stop logic
	return nil
}

// Packet represents a captured packet
type Packet struct {
	Timestamp time.Time
	Length    int
	// TODO: Add more packet fields
}
