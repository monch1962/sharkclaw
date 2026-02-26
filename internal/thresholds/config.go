package thresholds

import (
	"encoding/json"
	"os"
)

// Config contains all threshold configurations
type Config struct {
	Profiles map[string]ProfileConfig `json:"profiles"`
}

// ProfileConfig contains threshold values for a specific profile
type ProfileConfig struct {
	HandshakeRTTMS       HandshakeRTTThresholds        `json:"handshake_rtt_ms"`
	DNSRTTMS             DNSRTTThresholds              `json:"dns_rtt_ms"`
	IncompleteHandshakes IncompleteHandshakeThresholds `json:"incomplete_handshakes"`
	TCPResets            TCPResetThresholds            `json:"tcp_resets"`
	Retransmissions      RetransmissionThresholds      `json:"retransmissions"`
	DNSFailures          DNSFailureThresholds          `json:"dns_failures"`
}

// LoadFromConfig loads thresholds from a JSON config file
func LoadFromConfig(profile Profile) (Thresholds, error) {
	configFile := "thresholds.json"
	if len(configFile) == 0 {
		return defaults[profile], nil
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		// If config file doesn't exist, use defaults
		return defaults[profile], nil
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return defaults[profile], nil
	}

	profileConfig, exists := config.Profiles[string(profile)]
	if !exists {
		return defaults[profile], nil
	}

	return Thresholds{
		HandshakeRTTMS:       profileConfig.HandshakeRTTMS,
		DNSRTTMS:             profileConfig.DNSRTTMS,
		IncompleteHandshakes: profileConfig.IncompleteHandshakes,
		TCPResets:            profileConfig.TCPResets,
		Retransmissions:      profileConfig.Retransmissions,
		DNSFailures:          profileConfig.DNSFailures,
	}, nil
}

// LoadFromConfigFile loads thresholds from a specific config file
func LoadFromConfigFile(profile Profile, configFile string) (Thresholds, error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return defaults[profile], err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return defaults[profile], err
	}

	profileConfig, exists := config.Profiles[string(profile)]
	if !exists {
		return defaults[profile], nil
	}

	return Thresholds{
		HandshakeRTTMS:       profileConfig.HandshakeRTTMS,
		DNSRTTMS:             profileConfig.DNSRTTMS,
		IncompleteHandshakes: profileConfig.IncompleteHandshakes,
		TCPResets:            profileConfig.TCPResets,
		Retransmissions:      profileConfig.Retransmissions,
		DNSFailures:          profileConfig.DNSFailures,
	}, nil
}
