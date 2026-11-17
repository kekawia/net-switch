package updates

import "context"

type Backend interface {
	Start(context.Context, string) error
	Status() *Status
	Dismiss(string) error
}

type Status struct {
	Operation       string `json:"operation"`
	Phase           string `json:"phase"`
	Version         string `json:"version"`
	PreviousVersion string `json:"previousVersion,omitempty"`
	Downloaded      int64  `json:"downloaded,omitempty"`
	Size            int64  `json:"size,omitempty"`
	RebootRequired  bool   `json:"rebootRequired,omitempty"`
	Error           string `json:"error,omitempty"`
}

func (s Status) Busy() bool {
	switch s.Phase {
	case "downloading", "verifying", "ready", "preparing", "snapshotted", "applying", "checking", "rolling-back":
		return true
	}
	return false
}
