# Linux provenance: PR 1 contract slice

This is the first coherent part of the 27 October attribution design's PR 1,
not its completed kernel proof. Nothing here is registered in the engine.

## What is implemented

- Native-endian ABI 3 packet record (128 bytes), reader registration (48),
  key (8), and reader slot (256), with every C/Go field offset checked.
- An independent C writer and Go reader check actual bytes on each hosted
  architecture. The C header retains the pilot's MIT OR GPL-2.0-only licence.
- A pure acceptance predicate for copied synchronous read results: exactly
  one consume, positive syscall result, matching registration/sequence/epoch,
  stamped reader, single-reference packet, initialized cookie, healthy epoch.
  Failure returns no packet evidence. Missing successful reads request reload.
- Checked queue sizing. Q=500/C=512/R=4 needs 2,048 packet slots. The product's
  Q=16,384 needs 32,768; it cannot use the experiment's smaller allocation.

`PacketCaptured=1` is packet-cookie evidence only. Zero means incomplete.
The other status values remain unassigned. No result expresses a complete
application identity. Classification is carried without interpreting it as
application or kernel origin. CPU count is bounded, not the numeric CPU ID:
online CPU IDs can be sparse.

`CheckRead` consumes a **copy** of a slot, not mmap memory itself. The caller
must eventually supply the actual syscall outcome and freshly sampled health.
This slice does not implement arming, mmap synchronization, sequence allocation,
exactly-once consumption, thread locking, stamping, or collection reload.
The tests construct evidence; they do not demonstrate any kernel mechanism.

## Reference study and deliberate pilot reuse boundary

Read the complete attribution design and locked system design before coding.
Inspected pilot #100 at `0b34248902211515b8ffcef5575ba0d8ec425d96`, including
its ABI 1 records/header, generator, and vendored cilium/ebpf v0.22.0 mmap and
raw-tracepoint implementation. The package location and licence choice carry
forward. No old tuple decision, loader, workflow, dependency tree, or generated
object was imported: those cannot prove the new packet/read join unchanged.
The later kernel slice must deliberately restore the unchanged diagnostic
actor maps, tuple regression, and original reproducible generator.

Primary sources were inspected for ideas only; no upstream code was copied:

- [Linux v5.8 bpf_trace.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/trace/bpf_trace.c?h=v5.8):
  `trace_call_bpf` has the per-CPU active guard; `__bpf_trace_run` does not.
- [Linux v5.8 tun.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/tun.c?h=v5.8):
  transmit orphans before queueing; successful read consumes; failed copy frees;
  purge/resize use `tun_ptr_free`. This inspection is not the full lifetime audit.
- [cilium/ebpf v0.22.0 raw tracepoints](https://github.com/cilium/ebpf/blob/v0.22.0/link/raw_tracepoint.go)
  and [mmap memory](https://github.com/cilium/ebpf/blob/v0.22.0/memory.go):
  FD-owned raw attachment and aligned shared-memory access constraints.
- [Tailscale Linux port discovery](https://github.com/tailscale/tailscale/blob/main/portlist/portlist_linux.go):
  polling inode/process discovery is not historical packet provenance.

## Remaining PR 1 work (split before identity PR 2)

1. Kernel bridge: root-cgroup initialization, raw capture/terminal programs,
   checked CO-RE reads, fixed preallocated map manifest, FD-owned loader,
   mmap locked-reader protocol, sticky health and quiesced collection reload.
   Restore the pilot's diagnostic-only programs and generator deliberately.
2. Complete normal/fault objects and P1/P2 fixtures, including byte-identical
   and distinct-payload independent oracles, pre-loader sockets, nested terminal
   and perf-skip positive controls, actual pointer reuse, and independent
   capture/publication/deletion faults. Precondition failures must be fatal.
   Commit the exact hook manifest and path-by-path lifetime audit with evidence.
3. Signed-package/digest-pinned guest inputs, resolved native configs, static
   PID-1/initramfs, first successful boots followed by reproducibility builds.
   Pass both `owner-proof / floor-5.8-amd64` and
   `floor-5.8-arm64-tcg-correctness`, with their unchanged positive controls and
   fail-not-skip aggregator. Neither job exists in this contract-only slice.

Do not begin dependent identity integration on the strength of these pure
tests. PR 2 remains the retained-identity I1/I2 proof: execution generations,
validated sandbox/AppImage snapshots, cold exits, and shared-submitter unknowns.

## Release blocker effect

Zero of the sixteen declarations moves or clears. All remain unchanged in
`tests/linux/suite/release_linux_test.go`. This slice supplies only a shared
contract prerequisite to P1/P2; it supplies no acceptance measurement for:

- `overload.udp-sessions-per-app`, `overload.udp-sessions-total`
- `overload.tcp-connection-storm`, `overload.tcp-handshakes-in-flight`
- `overload.tcp-flows-total`, `overload.tcp-buffer-budget`
- `overload.rejection-notices-per-app`, `overload.rejection-notices-total`
- `overload.timewait-cap`, `overload.udp-pending-bytes`
- `overload.unknown-owner-limits`, `overload.tun-write-queue`
- `overload.memory-at-limit`, `protocol.flows-pagination`
- `capacity.mixed-caps`, `udp.fifty-destinations-one-session`

No changes to 99.5%, p95, identity denominators, capacity, recovery, or release
gate expectations. TCG correctness is not native performance evidence.

## Validation boundary

The small `Linux owner contract` workflow runs one job per hosted architecture,
at most two concurrently. It compiles C assertions, checks C/Go bytes and
requires all six named Go tests with zero skips. It does not execute BPF,
TUN, routes, an engine, or a guest. PR evidence links belong in the PR body so
adding evidence does not change the commit whose code was tested.
