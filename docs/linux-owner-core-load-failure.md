# First bridge load failure

Run [40875185221](https://github.com/kekawia/net-switch/actions/runs/40875185221)
built both objects successfully, then failed before the kernel fixtures ran on
[amd64](https://github.com/kekawia/net-switch/actions/runs/40875185221/job/123455075529)
and [arm64](https://github.com/kekawia/net-switch/actions/runs/40875185221/job/123455075379).
The ABI tests passed; neither architecture supplied bridge/P1/P2 evidence.

## Cause

The original `READ(dev, ctx->skbaddr->dev)` put the context-pointer access inside
`__builtin_preserve_access_index`. Both generated bridge objects in artifact
12898525401 contain the same erroneous CO-RE field-offset relocation:

```text
section=tracepoint/skb/consume_skb insnOffset=144 rootType=consume_event accessor=0:1 kind=0
```

This was checked directly in the original ZIP/ELF/BTF bytes in memory, without
loading BPF or writing artifact/log files locally. `consume_event` is our own
tracepoint-buffer declaration, not a kernel BTF type. The next relocation at
byte offset 152 is correctly rooted at `sk_buff`; subsequent roots are
`net_device` and `net`. The failed access is therefore not evidence that a
kernel field was renamed or disappeared.

[cilium's implementation](https://github.com/cilium/ebpf/blob/v0.22.0/btf/core.go)
uses 0x0bad2310 for an unresolved relocation. The emitted 195896080 sentinel
matches that value. The upstream [poison handling change](https://github.com/cilium/ebpf/pull/1351)
also describes this mechanism; it is not a workaround for our bad context type.

## Change and checks

Read `ctx->skbaddr` separately through the fixed tracepoint ABI, then use CO-RE
only for fields of the resulting kernel skb pointer. The loader now checks
the actual tracefs `skbaddr` field is an eight-byte pointer at offset eight
before loading. Missing/incompatible layouts refuse the proof, never guess.
No `field_exists` bypass is needed for a field that was never a kernel field.

The generated-object regression requires no relocation rooted at our private
context while retaining the kernel-field relocations, for normal and fault
objects. The original objects fail that condition. Hosted re-verification of
the changed objects and runtime fixtures remains necessary.

The complete Actions logs only contained the short error. The 27 omitted
lines were discarded by our formatting before logging, not hidden by GitHub.
Following [the verifier-error API](https://ebpf-go.dev/concepts/verifier-errors/),
both loaders now unwrap the typed VerifierError and include its full formatted
log while retaining the cause. A pure regression requires all 40 diagnostic
lines to survive nested wrapping. Future failures remain fatal and visible.
