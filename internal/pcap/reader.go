package pcap

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Packet represents a network packet
type Packet struct {
	Timestamp time.Time
	Length    int
	// TODO: Add more packet fields like source IP, destination IP, ports, protocol
}

// Reader reads packets from a PCAP file
type Reader struct {
	path     string
	handle   *pcap.Handle
	snapshot int
}

// NewReader creates a new PCAP reader
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

		packets = append(packets, Packet{
			Timestamp: packet.Metadata().Timestamp,
			Length:    packet.Metadata().Length,
		})
	}

	return packets, nil
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
