package output

import (
	"encoding/json"
	"fmt"
)

// Encode encodes data to JSON format
func Encode(data interface{}, pretty bool) (string, error) {
	var output string

	if pretty {
		// Pretty print with indentation
		outputBytes, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return "", fmt.Errorf("failed to marshal JSON with pretty print: %w", err)
		}
		output = string(outputBytes)
	} else {
		// Compact JSON (minified)
		outputBytes, err := json.Marshal(data)
		if err != nil {
			return "", fmt.Errorf("failed to marshal JSON: %w", err)
		}
		output = string(outputBytes)
	}

	return output, nil
}

// PrettyEncode encodes data to pretty-printed JSON
func PrettyEncode(data interface{}) (string, error) {
	return Encode(data, true)
}

// CompactEncode encodes data to minified JSON
func CompactEncode(data interface{}) (string, error) {
	return Encode(data, false)
}
