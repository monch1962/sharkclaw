package capture

import (
	analyze "github.com/sharkclaw/sharkclaw/internal/analyze"
)

// ToAnalyzerPacket converts capture.Packet to analyze.Packet
func ToAnalyzerPacket(capturePkt Packet) analyze.Packet {
	return analyze.Packet{
		Timestamp:       capturePkt.Timestamp,
		Length:          capturePkt.Length,
		SourceIP:        capturePkt.SourceIP,
		DestinationIP:   capturePkt.DestinationIP,
		SourcePort:      capturePkt.SourcePort,
		DestinationPort: capturePkt.DestinationPort,
		Protocol:        capturePkt.Protocol,
		SYN:             capturePkt.SYN,
		ACK:             capturePkt.ACK,
		RST:             capturePkt.RST,
		SeqNumber:       capturePkt.SeqNumber,
		AckNumber:       capturePkt.AckNumber,
	}
}

// Convert captures packets to analyzer format
func Convert(capturePackets []Packet) []analyze.Packet {
	analyzerPackets := make([]analyze.Packet, len(capturePackets))
	for i, pkt := range capturePackets {
		analyzerPackets[i] = ToAnalyzerPacket(pkt)
	}
	return analyzerPackets
}
