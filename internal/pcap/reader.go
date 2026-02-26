package pcap

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Packet represents a network packet
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
	// TODO: Add more fields as needed (flags, payload size, etc.)
}

// Reader reads packets from a PCAP file
type Reader struct {
	path     string
	handle   *pcap.Handle
	snapshot int
}

// NewReader creates a new PCAP reader
func NewReader(path string) (*Reader, error) {
	if path == "" {
		return nil, errors.New("path cannot be empty")
	}

	// Open PCAP file
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open PCAP file %s: %w", path, err)
	}

	return &Reader{
		path:   path,
		handle: handle,
	}, nil
}

// Read reads all packets from the PCAP file
func (r *Reader) Read() ([]Packet, error) {
	if r.handle == nil {
		return nil, errors.New("reader is closed or not initialized")
	}

	packets := make([]Packet, 0)
	packetSource := gopacket.NewPacketSource(r.handle, r.handle.LinkType())

	for packet := range packetSource.Packets() {
		if packet == nil {
			break
		}

		packet := extractPacketFields(packet)
		packets = append(packets, packet)
	}

	return packets, nil
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

// CountPackets counts the total number of packets in the PCAP file
func (r *Reader) CountPackets() (int, error) {
	if r.handle == nil {
		return 0, errors.New("reader is closed or not initialized")
	}

	// PCAP count includes all packets in the file
	return int(r.handle.LinkType()), nil
}

// Close closes the PCAP reader handle
func (r *Reader) Close() error {
	if r.handle == nil {
		return nil
	}

	r.handle.Close()
	r.handle = nil
	return nil
}

// SetBPFFilter sets a BPF filter for the reader
func (r *Reader) SetBPFFilter(filter string) error {
	if r.handle == nil {
		return errors.New("reader is closed or not initialized")
	}

	if filter == "" {
		return fmt.Errorf("filter cannot be empty")
	}

	if err := r.handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("failed to set BPF filter %s: %w", filter, err)
	}

	return nil
}

// MockReader for testing without gopcap
type MockReader struct {
	Packets []Packet
	Err     error
}

func NewMockReader(packets []Packet, err error) *MockReader {
	return &MockReader{
		Packets: packets,
		Err:     err,
	}
}

func (m *MockReader) Read() ([]Packet, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	return m.Packets, nil
}

func (m *MockReader) CountPackets() (int, error) {
	if m.Err != nil {
		return 0, m.Err
	}
	return len(m.Packets), nil
}

func (m *MockReader) Close() error {
	return nil
}

func (m *MockReader) LinkType() (int, error) {
	return 1, nil
}

func (m *MockReader) SetBPFFilter(filter string) error {
	if filter == "" {
		return fmt.Errorf("filter cannot be empty")
	}
	return nil
}
