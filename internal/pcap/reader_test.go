package pcap

import (
	"testing"
	"time"
)

func TestNewReader(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "valid PCAP path",
			path:    "test.pcap",
			wantErr: false,
		},
		{
			name:    "valid PCAPNG path",
			path:    "test.pcapng",
			wantErr: false,
		},
		{
			name:    "empty path",
			path:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewReader(tt.path)
			if tt.wantErr {
				if err == nil {
					t.Errorf("NewReader() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("NewReader() unexpected error: %v", err)
			}
		})
	}
}

func TestReaderRead(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "read from valid PCAP",
			path:    "test.pcap",
			wantErr: false,
		},
		{
			name:    "read from valid PCAPNG",
			path:    "test.pcapng",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader, err := NewReader(tt.path)
			if err != nil {
				t.Skip("Skipping test: could not create reader")
			}

			packets, err := reader.Read()
			if tt.wantErr {
				if err == nil {
					t.Errorf("Read() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Read() unexpected error: %v", err)
			}

			if packets == nil {
				t.Error("Read() returned nil packets")
			}
		})
	}
}

func TestReaderClose(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "close valid reader",
			path:    "test.pcap",
			wantErr: false,
		},
		{
			name:    "close reader with invalid path",
			path:    "/nonexistent/file.pcap",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader, err := NewReader(tt.path)
			if err != nil {
				t.Skip("Skipping test: could not create reader")
			}

			err = reader.Close()
			if err != nil {
				t.Errorf("Close() unexpected error: %v", err)
			}
		})
	}
}

func TestReaderCountPackets(t *testing.T) {
	tests := []struct {
		name     string
		packets  []Packet
		wantErr  bool
		minPacks int
	}{
		{
			name: "count packets in mock reader",
			packets: []Packet{
				{Timestamp: time.Now(), Length: 100},
				{Timestamp: time.Now().Add(1 * time.Second), Length: 200},
			},
			wantErr:  false,
			minPacks: 2,
		},
		{
			name:     "count zero packets",
			packets:  []Packet{},
			wantErr:  false,
			minPacks: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := NewMockReader(tt.packets, nil)

			count, err := reader.CountPackets()
			if tt.wantErr {
				if err == nil {
					t.Errorf("CountPackets() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("CountPackets() unexpected error: %v", err)
			}

			if count < tt.minPacks {
				t.Errorf("CountPackets() expected at least %d packets, got %d", tt.minPacks, count)
			}
		})
	}
}
