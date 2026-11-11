# Third-party software

Net Switch's own code is under the MIT license (see `LICENSE`). The installer
also ships the separate programs below, each under its own license. They run as
separate programs; Net Switch does not modify them. The one exception is the Go
code compiled into Net Switch's own helper program (see the end). "MIT" applies
to Net Switch's code only, not to the installer as a whole.

## Wintun 0.14.1

- What it does here: the Windows driver behind the virtual network adapter,
  from the official
  [wintun-0.14.1.zip](https://www.wintun.net/builds/wintun-0.14.1.zip) build.
- Copyright (C) WireGuard LLC. Distributed under the Wintun prebuilt-binaries
  license, which allows shipping it unmodified with other software:
  `licenses\wintun-LICENSE.txt`.

## Node.js

- What it does here: runs Net Switch (`runtime\node.exe`).
- Copyright Node.js contributors, under the MIT license, with notices for the
  components Node.js includes.
- License text in the installed copy: `runtime\LICENSE` and
  `licenses\node-LICENSE.txt`, taken unchanged from the official Node.js build.

## Lucide icons

- What it does here: the shapes of several icons in the window and tray.
- ISC license (with some icons from Feather under MIT): see
  `licenses\lucide-ISC.txt`.

## Go runtime and golang.org/x/sys

The unshipped Net Switch 1.0 Linux desktop also uses
[godbus/dbus v5.2.4](https://github.com/godbus/dbus/tree/v5.2.4), under BSD-2-Clause,
to show pairing codes through the owner's session bus. Its license is retained
in `vendor/github.com/godbus/dbus/v5/LICENSE`.

- What it does here: `helper\netswitch-helper.exe` is Net Switch's own small
  program (its source is in the repository's `helper` folder) that reads the
  line meters and the connections that go around routing. It is written in Go, so the Go runtime
  and standard library (Go 1.27.3) and
  [golang.org/x/sys](https://pkg.go.dev/golang.org/x/sys) v0.49.0 are compiled
  into it, unmodified.
- Copyright 2009 The Go Authors. Both are under the same BSD-style
  (3-clause) license. License text in the installed copy:
  `licenses\go-LICENSE.txt`, taken unchanged from the official Go release.
  golang.org/x/sys ships the same text.

## Net Switch 1.0 engine core (not yet shipped)

The new engine's own code is MIT licensed. The list below comes from the compiled
Linux production binary, generated and checked by `scripts/engine-notices.mjs`.
It does not replace the 0.3.x programs listed above. Windows uses the shared core
and its native Windows platform implementation.

- The unshipped `netswitch-cleanup` tool includes the Go runtime and golang.org/x/sys under the same BSD-3-Clause licenses as the helper.

gVisor is copyright The gVisor Authors. Net Switch modifies eleven files,
each with a modification notice. `third_party/gvisor-local-close.patch` contains
the opt-in local-app close admission, TIME_WAIT handling, retained-buffer budget
and buffer accounting hooks in five files. It also adds
`dispatcher_netswitch_test.go`, marked "Net Switch addition, not upstream".
`third_party/gvisor-provenance.patch` carries packet provenance across packet
clones, conservative IPv4/IPv6 fragment reassembly and TCP forwarder requests in
three files (`packet_buffer.go`, `reassembler.go` and `forwarder.go`), and adds
`provenance_netswitch_test.go`, marked "Net Switch addition, not upstream".
`third_party/gvisor-rto-recovery.patch` changes `rack.go` and `snd.go` to preserve
TCP timeout recovery until its flight drains, independently of the opt-in hooks.
`third_party/gvisor-sack-cache.patch` shares a bounded SACK node cache in
`sack_scoreboard.go` so idle connections need no private node free list.
`third_party/gvisor-tcp-retry-limit.patch` changes `snd.go` so only retransmission
timeouts count against a connection's retry limit, not fast or RACK resends.
`third_party/gvisor-tlp-recovery.patch` changes `rack.go` to align RACK tail-loss
probe scheduling and episode completion with RFC 8985.
The generator applies the reproducible patches in filename order. License and
authors are preserved in the generated source and vendor trees. wireguard-go is
copyright WireGuard LLC and is used unmodified for Linux TUN I/O. cilium/ebpf is
copyright Nathan Sweet, Cloudflare and Authors of Cilium and is used unmodified
for Linux eBPF program and map loading. netlink and netns are used unmodified for
Linux routing and network namespaces.

<!-- engine-modules:start -->
Go 1.27.3 runtime and standard library: BSD-3-Clause (the toolchain's LICENSE and PATENTS).

- github.com/cilium/ebpf `v0.22.0`, MIT; license: `vendor/github.com/cilium/ebpf/LICENSE`.
- github.com/godbus/dbus/v5 `v5.2.4`, BSD-2-Clause; license: `vendor/github.com/godbus/dbus/v5/LICENSE`.
- github.com/google/btree `v1.1.2`, Apache-2.0; license: `vendor/github.com/google/btree/LICENSE`.
- github.com/vishvananda/netlink `v1.3.1`, Apache-2.0; license: `vendor/github.com/vishvananda/netlink/LICENSE`.
- github.com/vishvananda/netns `v0.0.5`, Apache-2.0; license: `vendor/github.com/vishvananda/netns/LICENSE`.
- golang.org/x/exp `v0.0.0-20250711185948-6ae5c78190dc`, BSD-3-Clause; license: `vendor/golang.org/x/exp/LICENSE`.
- golang.org/x/net `v0.59.0`, BSD-3-Clause; license: `vendor/golang.org/x/net/LICENSE`.
- golang.org/x/sys `v0.49.0`, BSD-3-Clause; license: `vendor/golang.org/x/sys/LICENSE`.
- golang.org/x/time `v0.15.0`, BSD-3-Clause; license: `vendor/golang.org/x/time/LICENSE`.
- golang.zx2c4.com/wireguard `v0.0.0-20261006164505-2631ce99a06f`, MIT; license: `vendor/golang.zx2c4.com/wireguard/LICENSE`.
- gvisor.dev/gvisor `v0.0.0-20261017122056-1b7906fdee8c`, Apache-2.0; license: `third_party/gvisor/LICENSE`.
<!-- engine-modules:end -->
