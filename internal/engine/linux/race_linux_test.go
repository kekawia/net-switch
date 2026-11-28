//go:build linux && race

package linux

import "time"

const raceInstrumented = true

// The race detector slows a typical program 2 to 20 times
// (https://go.dev/doc/articles/race_detector, "Runtime Overhead"). On a busy
// 2-CPU runner a real UDPFor overran the production 8 ms and failed a test
// that checks correctness, not speed (run 46092530421). Race builds give a
// lookup 25 times the budget; the acceptance suite's lookup.p95-measured gate
// still holds production to 8 ms. Tests that wait for this deadline keep their
// one-second outer contexts well above two of these.
func init() { lookupBudget = 200 * time.Millisecond }
