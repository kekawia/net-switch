//go:build windows

package wintun

import (
	"errors"
	"fmt"
	"math"
)

type performanceSample struct {
	Status string   `json:"status"`
	Value  *float64 `json:"value"` // JSON null means absent, never zero throughput
	Error  string   `json:"error,omitempty"`
	Pair   int      `json:"pair"`
	Mode   string   `json:"mode"`
	Metric string   `json:"metric"`
	cause  error
}

func (s *performanceSample) finish(value float64, err error) {
	if err == nil && (value <= 0 || math.IsNaN(value) || math.IsInf(value, 0)) {
		err = fmt.Errorf("unusable measured value %g", value)
	}
	s.Status, s.Value, s.Error, s.cause = "valid", &value, "", nil
	if err != nil {
		s.Status, s.Value, s.Error, s.cause = "invalid", nil, err.Error(), err
	}
}

func newPerformanceSamples(pairs int, mode, metric string) []performanceSample {
	samples := make([]performanceSample, pairs)
	for i := range samples {
		samples[i] = performanceSample{Status: "invalid", Error: "sample not executed", Pair: i, Mode: mode, Metric: metric}
	}
	return samples
}

// referenceFault reports whether a sample of the signed DLL failed on the
// DLL's own account: its reader rejected a ring entry, or it delivered bytes
// that were never sent. Both are the 0.14.1 driver's defects seen through the
// official library. They are driver evidence and no measure of our session,
// so they are reported and never fail a comparison (the release gate approved
// on 2026-11-10). The in-process reference is our own reader and writer and
// is never excused.
func referenceFault(s performanceSample) bool {
	return s.Mode == "dll" && (errors.Is(s.cause, ErrCorrupt) || errors.Is(s.cause, errPayloadIntegrity))
}

// validPairs is how many of the matched pairs a ratio needs: nine of twelve.
// The others may be lost to reference faults.
func validPairs(pairs int) int { return (3*pairs + 3) / 4 }

var errTooFewPairs = errors.New("too few pairs for a ratio")

// pairedSampleRatios returns one ratio per pair whose two samples are valid.
// A pair whose DLL sample is a reference fault is left out; every other
// invalid sample fails the comparison, as does having too few pairs left.
func pairedSampleRatios(ours, dll []performanceSample, reference ...string) ([]float64, error) {
	mode := "dll"
	if len(reference) != 0 {
		mode = reference[0]
	}
	if len(ours) == 0 || len(ours) != len(dll) {
		return nil, fmt.Errorf("integrity-invalid comparison: incomplete matched pairs ours=%d DLL=%d", len(ours), len(dll))
	}
	var invalid error
	var a, b []float64
	for i := range ours {
		usable := true
		for _, side := range []struct {
			samples []performanceSample
			mode    string
		}{{ours, "ours"}, {dll, mode}} {
			s := side.samples[i]
			identified := s.Pair == i && s.Mode == side.mode && s.Metric == ours[0].Metric
			if identified && referenceFault(s) {
				usable = false
			} else if !identified || s.Status != "valid" || s.Value == nil || s.Error != "" {
				cause := s.cause
				if cause == nil {
					cause = fmt.Errorf("%s (status=%s, pair=%d, mode=%s, metric=%s)", s.Error, s.Status, s.Pair, s.Mode, s.Metric)
				}
				invalid = errors.Join(invalid, fmt.Errorf("pair=%d mode=%s metric=%s: %w", i, side.mode, s.Metric, cause))
				usable = false
			}
		}
		if usable {
			a, b = append(a, *ours[i].Value), append(b, *dll[i].Value)
		}
	}
	if invalid != nil {
		return nil, fmt.Errorf("integrity-invalid comparison: %w", invalid)
	}
	if len(a) < validPairs(len(ours)) {
		return nil, fmt.Errorf("integrity-invalid comparison: only %d of %d pairs are left after reference faults, fewer than %d: %w", len(a), len(ours), validPairs(len(ours)), errTooFewPairs)
	}
	ratios, err := pairedRatios(a, b)
	if err != nil {
		return nil, fmt.Errorf("integrity-invalid comparison: %w", err)
	}
	return ratios, nil
}
