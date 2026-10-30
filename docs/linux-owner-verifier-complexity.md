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

Keep the bounded hold as 2,500 outer quanta of 32 straight-line `bpf_ktime_get_ns`
calls (80,000-call ceiling), polling the release word and 20 ms deadline between
quanta. Explicitly prevent outer-loop unrolling (`#pragma clang loop unroll(disable)`);
unroll only the 32-call inner quantum (`#pragma unroll`). `proof_hold(32, ...)`
is also included in `capture` for the real kernel stale-record mutation proof.
This removes uncertain per-call branches so the pending jump stack stays well
below 8,192 without changing packet capture, retirement, identity or health
rules in the normal object.

No `bpf_loop` helper, tail-call map or newer atomic is introduced. This retains
5.8-capable constructs, while actual 5.8 verification remains a floor-guest gate.

Research included the kernel's
[state-pruning description](https://kernel.org/doc/html/latest/bpf/verifier.html),
cilium/ebpf's [log-handling change](https://github.com/cilium/ebpf/pull/1693),
and Cilium's [older ARM64 tail-call compatibility report](https://github.com/cilium/cilium/issues/33408).
The log-handling fix does not solve branch explosion; using tail calls would
introduce additional old-kernel/architecture obligations. No upstream code was
copied. The fixed-quantum structure is original.

## Verified hosted execution (run 40934322738)

In [run 40934322738](https://github.com/kekawia/net-switch/actions/runs/40934322738)
(head `e5fc011c`, jobs [123667040419](https://github.com/kekawia/net-switch/actions/runs/40934322738/job/123667040419) amd64 and
[123667040491](https://github.com/kekawia/net-switch/actions/runs/40934322738/job/123667040491) arm64, kernel `7.0.0-1017-azure`),
all normal and fault programs verified and loaded cleanly on both architectures:

```text
VERIFIER fault=false program=capture processed 307 insns (limit 1000000) max_states_per_insn 1 total_states 24 peak_states 24 mark_read 0
VERIFIER fault=false program=consume processed 338 insns (limit 1000000) max_states_per_insn 1 total_states 23 peak_states 23 mark_read 0
VERIFIER fault=false program=freed processed 338 insns (limit 1000000) max_states_per_insn 1 total_states 23 peak_states 23 mark_read 0
VERIFIER fault=false program=init_egress_cookie processed 20 insns (limit 1000000) max_states_per_insn 0 total_states 2 peak_states 2 mark_read 0
VERIFIER fault=false program=perf_consume processed 77 insns (limit 1000000) max_states_per_insn 0 total_states 7 peak_states 7 mark_read 0

VERIFIER fault=true program=capture processed 107988 insns (limit 1000000) max_states_per_insn 4 total_states 4435 peak_states 4435 mark_read 0
VERIFIER fault=true program=consume processed 108174 insns (limit 1000000) max_states_per_insn 4 total_states 4445 peak_states 4444 mark_read 0
VERIFIER fault=true program=freed processed 108174 insns (limit 1000000) max_states_per_insn 4 total_states 4445 peak_states 4444 mark_read 0
VERIFIER fault=true program=init_egress_cookie processed 20 insns (limit 1000000) max_states_per_insn 0 total_states 2 peak_states 2 mark_read 0
VERIFIER fault=true program=observe_nested_free processed 92 insns (limit 1000000) max_states_per_insn 0 total_states 8 peak_states 8 mark_read 0
VERIFIER fault=true program=perf_consume processed 77 insns (limit 1000000) max_states_per_insn 0 total_states 7 peak_states 7 mark_read 0
```

The generated-object test (`scripts/generate-owner-bpf.mjs`) requires 33 static
clock-call sites (one start plus 32 body calls) in each fault `capture`/`consume`/`freed`
program, and zero in the normal versions.

