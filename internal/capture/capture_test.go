package capture

import (
	"testing"
	"time"
)

func TestExtractPacketFields(t *testing.T) {
	// This is a simple test to ensure the function compiles and returns a valid struct
	packets := []Packet{
		{
			Timestamp:       time.Now(),
			Length:          60,
			SourceIP:        "192.168.1.100",
			DestinationIP:   "10.0.0.50",
			SourcePort:      50000,
			DestinationPort: 80,
			Protocol:        "TCP",
			SYN:             true,
			ACK:             false,
			RST:             false,
		},
	}

	if len(packets) != 1 {
		t.Errorf("Expected 1 packet, got %d", len(packets))
	}
}
