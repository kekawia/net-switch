/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
#include <stdio.h>
#include <stddef.h>
#include <linux/bpf.h>
#include "../bpf/provenance.h"

_Static_assert(offsetof(struct bpf_prog_info, id) == 4, "program id offset");
_Static_assert(offsetof(struct bpf_prog_info, recursion_misses) == 208, "misses offset");
_Static_assert(sizeof(((struct bpf_prog_info *)0)->recursion_misses) == 8, "misses size");

/* Independent C writer, consumed by Go. Never loads a BPF program. */
int main(void)
{
    struct ns_reader_slot slot = {0};
    slot.control.abi = 3;
    slot.control.registration = 0x1020304050607080ULL;
    slot.control.epoch = 0x1122334455667788ULL;
    slot.control.sequence = 0x8877665544332211ULL;
    slot.control.armed = 0;
    slot.completion.count = 1;
    slot.completion.sequence = slot.control.sequence;
    slot.completion.registration = slot.control.registration;
    slot.completion.terminal = NS_TERMINAL_CONSUME;
    slot.completion.status = NS_PACKET_CAPTURED;
    slot.packet.abi = NS_PROVENANCE_ABI;
    slot.packet.status = NS_PACKET_CAPTURED;
    slot.packet.epoch = slot.control.epoch;
    slot.packet.ifindex = 0x12345678;
    slot.packet.netns = 0x87654321;
    slot.packet.cpu = 7;
    slot.packet.classification = 0x10293847;
    slot.packet.serial = 0xabcdef0123456789ULL;
    slot.packet.cookie = 0x123456789abcdef0ULL;
    slot.packet.length = 1500;
    slot.packet.users = 1;
    if (fwrite(&slot, sizeof(slot), 1, stdout) != 1)
        return 1;
    return fflush(stdout) == 0 ? 0 : 1;
}
