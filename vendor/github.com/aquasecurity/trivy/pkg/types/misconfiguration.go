package types

import ftypes "github.com/aquasecurity/fanal/types"

// DetectedMisconfiguration holds detected misconfigurations
type DetectedMisconfiguration struct {
	Type        string             `json:",omitempty"`
	ID          string             `json:",omitempty"`
	Title       string             `json:",omitempty"`
	Description string             `json:",omitempty"`
	Message     string             `json:",omitempty"`
	Namespace   string             `json:",omitempty"`
	Query       string             `json:",omitempty"`
	Resolution  string             `json:",omitempty"`
	Severity    string             `json:",omitempty"`
	PrimaryURL  string             `json:",omitempty"`
	References  []string           `json:",omitempty"`
	Status      MisconfStatus      `json:",omitempty"`
	Layer       ftypes.Layer       `json:",omitempty"`
	IacMetadata ftypes.IacMetadata `json:",omitempty"`

	// For debugging
	Traces []string `json:",omitempty"`
}

// MisconfStatus represents a status of misconfiguration
type MisconfStatus string

const (
	// StatusPassed represents successful status
	StatusPassed MisconfStatus = "PASS"

	// StatusFailure represents failure status
	StatusFailure MisconfStatus = "FAIL"

	// StatusException Passed represents the status of exception
	StatusException MisconfStatus = "EXCEPTION"
)
