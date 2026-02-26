package capture

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Packet represents a captured network packet
type Packet struct {
	Timestamp       time.Time
	Length          int
	SourceIP        string
	DestinationIP   string
	SourcePort      int
	DestinationPort int
	Protocol        string
	SYN             bool
	ACK             bool
	RST             bool
	SeqNumber       uint32
	AckNumber       uint32
}

// Capturer captures network traffic
type Capturer struct {
	handle   *pcap.Handle
	iface    string
	bpf      string
	interval time.Duration
}

// NewCapturer creates a new network capturer
func NewCapturer(iface string, bpf string, interval time.Duration) (*Capturer, error) {
	// Open live capture
	handle, err := pcap.OpenLive(iface, 65535, true, interval)
	if err != nil {
		return nil, fmt.Errorf("failed to open capture on interface %s: %w", iface, err)
	}

	return &Capturer{
		handle:   handle,
		iface:    iface,
		bpf:      bpf,
		interval: interval,
	}, nil
}

// Capture captures packets for a specified duration
func (c *Capturer) Capture(duration time.Duration) ([]Packet, error) {
	packets := make([]Packet, 0)

	// Set BPF filter if specified
	if c.bpf != "" {
		if err := c.handle.SetBPFFilter(c.bpf); err != nil {
			return nil, fmt.Errorf("failed to set BPF filter: %w", err)
		}
	}

	// Create packet source
	packetSource := gopacket.NewPacketSource(c.handle, c.handle.LinkType())

	// Capture packets for the specified duration
	timeout := time.After(duration)
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}

			packets = append(packets, extractPacketFields(packet))

		case <-timeout:
			return packets, nil

		case <-ticker.C:
			// Continue capturing
		}
	}
}

// extractPacketFields extracts detailed packet fields from gopacket
func extractPacketFields(packet gopacket.Packet) Packet {
	var result Packet

	// Extract metadata
	result.Timestamp = packet.Metadata().Timestamp
	result.Length = packet.Metadata().Length

	// Extract IP layer
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)
		result.SourceIP = ipv4.SrcIP.String()
		result.DestinationIP = ipv4.DstIP.String()
	}

	if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6 := ipv6Layer.(*layers.IPv6)
		result.SourceIP = ipv6.SrcIP.String()
		result.DestinationIP = ipv6.DstIP.String()
	}

	// Extract transport layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)

		result.Protocol = "TCP"
		result.SourcePort = int(tcp.SrcPort)
		result.DestinationPort = int(tcp.DstPort)
		result.SYN = tcp.SYN
		result.ACK = tcp.ACK
		result.RST = tcp.RST
		// TODO: Extract sequence and acknowledgment numbers when available
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)

		result.Protocol = "UDP"
		result.SourcePort = int(udp.SrcPort)
		result.DestinationPort = int(udp.DstPort)
	}

	// Extract payload size if needed
	if len(packet.Data()) > 0 {
		result.Length = len(packet.Data())
	}

	return result
}

// Close closes the capture handle
func (c *Capturer) Close() {
	if c.handle != nil {
		c.handle.Close()
	}
}
