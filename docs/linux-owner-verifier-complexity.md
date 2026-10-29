# Fault hold verifier complexity

Run [40888479709](https://github.com/kekawia/net-switch/actions/runs/40888479709),
head e85dfc63175b985db0e06819cfe2cd2a57caf706, reached kernel verification but
rejected the fault object's consume/free programs. Normal-object tests ran.

## Cause established from the trace

The [amd64 log](https://github.com/kekawia/net-switch/actions/runs/40888479709/job/123499599744)
contains failures of both `consume` and `freed`. The
[arm64 log](https://github.com/kekawia/net-switch/actions/runs/40888479709/job/123499599585)
reports `consume` as the first failed program in each collection load. A failed
collection does not establish that every other program was attempted.

Both logs report this failure summary:

```text
The sequence of 8193 jumps is too complex.
processed 49680 insns (limit 1000000) max_states_per_insn 4 total_states 864 peak_states 864 mark_read 0
```

The repeated instructions are the hold's release-word load (fault-map offset
48), conditional release exit, clock helper, conditional deadline exit and a
backward loop branch (`goto pc-12`). Thus the compiler retained a bounded loop;
it did not unroll the whole 20,000 iterations. Each iteration gives the verifier
two fresh uncertain exits. The pending exploration stack reaches its limit
before the instruction budget is exhausted. Packet-slot branching is not the
construct responsible for this trace.

`BPF_COMPLEXITY_LIMIT_JMP_SEQ` is 8,192 in the inspected
[v5.8](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/bpf/verifier.c?h=v5.8),
[v7.0](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/bpf/verifier.c?h=v7.0)
and [v7.3](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/bpf/verifier.c?h=v7.3)
sources. The check compares `env->stack_size` against that limit. This is not
the million-instruction limit or the reported total-state counter.

## Restructure

Keep the same ceiling of 20,000 clock calls, as 1,250 bounded quanta of 16
straight-line calls. Poll the release word and 20 ms deadline between quanta.
Explicitly prevent outer-loop unrolling; unroll only the 16-call inner quantum.
This removes most uncertain exits without extending the work ceiling or
changing packet capture, retirement, identity or health rules. Release/deadline
observation now has 16-call granularity, which is explicit rather than claimed
identical timing. The positive controls still require actual kernel skips and
refuse a hold that failed to overlap the stimulus.

No `bpf_loop` helper, tail-call map or newer atomic is introduced. This retains
5.8-capable constructs, but actual 5.8 verification remains a floor-guest gate,
not a claim based on successful compilation.

Research included the kernel's
[state-pruning description](https://kernel.org/doc/html/latest/bpf/verifier.html),
cilium/ebpf's [log-handling change](https://github.com/cilium/ebpf/pull/1693),
and Cilium's [older ARM64 tail-call compatibility report](https://github.com/cilium/cilium/issues/33408).
The log-handling fix does not solve branch explosion; using tail calls would
introduce additional old-kernel/architecture obligations. No upstream code was
copied. The smaller fixed-work structure is original.

## Evidence required from the next run

The loader requests branch and statistics logs from the first load. Each
success must contain a `processed ... insns` summary, which the fixture prints
as `VERIFIER fault=<bool> program=<name> ...` in stable name order. A missing
summary fails the proof. Only cloned summary strings are retained after load;
large successful instruction logs are released. Failure logs remain complete.

The generated-object test also requires 17 static clock-call sites (one start
plus 16 body calls) in each fault consume/free program, and zero in the normal
versions. This catches accidental outer unrolling or removal of the work body.
New successful instruction/state counts are pending hosted execution; none is
inferred from the source change.

Two initial log filters were too broad and slow. Their local read processes
were stopped and the relevant lines re-read with narrow native filtering. No
CI run was cancelled and no log was saved to disk.

## Positive evidence retained from the failed run

The independent perf-skip control ran with no injected skips:

```text
amd64: baseline_raw=32 baseline_perf=32 sent=10000 raw=10000 perf=9360 missing=640 stress_lookups=734871 injected_skips=0
arm64: baseline_raw=32 baseline_perf=32 sent=10000 raw=10000 perf=9872 missing=128 stress_lookups=817006 injected_skips=0
```

The failure does not erase these observations, and these observations do not
turn the overall run green or qualify the fault-object controls.
