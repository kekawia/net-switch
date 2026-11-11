//go:build linux

package ownerbpf

type FloorGuestSuite struct {
	Name    string
	Pattern string
	Timeout string
}

// FloorGuestSuites returns the ordered test suites run inside the Linux 5.8
// floor guest. Bridge proofs are split into epoch and lifetime suites so
// software-emulated ARM64 TCG runs keep per-process BPF verifier loads well
// within each go test timeout.
func FloorGuestSuites() []FloorGuestSuite {
	return []FloorGuestSuite{
		{
			Name:    "kernel-proof",
			Pattern: "^TestKernelProof$",
			Timeout: "5m",
		},
		{
			Name:    "bridge-epoch-proof",
			Pattern: "^(TestBridgeBurstCost|TestBridgeDeletionFaultReload|TestBridgePreemptedReader|TestBridgeNestedFreeSkip|TestBridgeStaleRecordMutation|TestBridgeSingleReaderPostDrainAndForeignConsume)$",
			Timeout: "15m",
		},
		{
			Name:    "bridge-lifetime-proof",
			Pattern: "^(TestBridgePerfSkippedConsumes|TestBridgeQueuedPair|TestBridgeConcurrentDrops|TestBridgePointerReuse|TestBridgeInfoLayout|TestBridgeRelocations|TestBridgePerfCounterBaseline|TestBridgePreLoaderSocket|TestBridgeReadLifetimes)$",
			Timeout: "15m",
		},
		{
			Name:    "identity-proof",
			Pattern: "^TestIdentity",
			Timeout: "10m",
		},
		{
			Name:    "sender-lifecycle-proof",
			Pattern: "^(TestSenderP3|TestSenderEngineSpecLoad|TestOffloadAndFragmentsP4|TestLifecycleL1|TestLifecycleL2)$",
			Timeout: "10m",
		},
	}
}
