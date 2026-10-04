.. SPDX-License-Identifier: GPL-2.0

============================
Memcompress reclaim behavior
============================

Memcompress stores anonymous memory in a compressed RAM pool and represents
the displaced mappings with reserved swap-type tokens. It needs the swap
infrastructure enabled by CONFIG_SWAP; an active ordinary swap device is
not required for this RAM-backed path.

Execution and ownership
=======================

With CONFIG_MEMCOMPRESS, each memory node starts kreclaimd<N>/<index> tasks
alongside kswapd. For C online CPUs at startup there are max(C, 2) - 1 workers,
of which max(C, 3) - 2 are regular workers and any remaining worker is a burst
worker. Eight online CPUs therefore give kreclaimd0/0 through kreclaimd0/5
and the burst worker kreclaimd0/6 on node zero. Indices do not designate CPUs;
workers may run on the online CPU mask and retain the default scheduling
policy. CPU hotplug does not resize the worker set.

The workers share a 1024-item FIFO and remove up to eight items per batch.
Kswapd queues eligible anonymous folios before leasing a compression context.
A successful submission transfers the held folio lock and isolation reference
and contributes no reclaimed pages to the submitting scan. The worker pins
the anon_vma, reserves tokens, unmaps and flushes deferred TLB invalidations,
then stores the contents. Failure restores PTEs while the folio lock and
anon_vma pin are held and puts the folio back on its LRU. Queue rejection
retains the synchronous path. Reclaim performed outside the node's kswapd
remains synchronous, including caller-driven direct and targeted reclaim.
Kswapd can also enqueue work while scanning a soft-limit target memcg.

The same FIFO accepts eligible writepage work after pageout has cleared the
dirty flag and set reclaim. This transfers the lock with an extra folio
reference; the original caller retains LRU ownership. The worker rechecks the
mapping, invokes writepage with its own writeback_control and no swap plug,
and drops its reference after handling the callback result. Rejection falls
back to synchronous writepage. Shmem is excluded from this dispatch. This is
ordinary reclaim writeback, independent of any memcompress packed swap drain.
Writepage dispatch remains available when compression is disabled at runtime.

Contexts are reusable codec resources shared with synchronous reclaim. Worker
count does not imply the same number of simultaneously available contexts.
Queue items and inflight base pages are separate units. The original LRU scan
finishes its NR_ISOLATED accounting; workers do not subtract it a second time.
Queued compression folios remain represented by inflight accounting until
completion, even after the original scan has returned.

Feedback and bounded waits
==========================

At 512 queued items kswapd requests burst processing. At 768 items it can wait
one jiffy for the queue to shrink by 64 items. The burst worker drains work
until the FIFO is empty. Ordinary worker waits are nonexclusive and can wake
multiple workers. These thresholds match the examined vendor policy; they
are not temperature, latency or power guarantees.

Workers count only successful compression into their completion cursor and
PGSTEAL statistics. Kswapd consumes each new completion once, separately from
synchronous reclaim, and reevaluates its scan priority and compaction target.
It can request up to three one-jiffy completion waits per balance invocation,
for at most 32 successful pages per wait. Failure drainage also releases a
wait when inflight reaches its floor, but contributes no reclaimed pages.
Success clears the node's kswapd failure history, including late completions.

Order-zero global direct reclaim tracks fresh-reservation context contention.
Eight consecutive precheck rejections or 32 rejected base pages stop fresh
reservation attempts for that node scan. Existing reservations and ordinary
swap fallback remain available. The allocating task may wait once for one
jiffy if another reclaim is inflight. Only a changed successful-page cursor
permits the allocator retry hint; failure drainage does not manufacture
reclaimed pages. Targeted, proactive, hibernation and kernel-worker reclaim
do not use this direct-feedback policy.

memcompress_reclaim_queue() itself only adds base pages to inflight accounting;
it is not the FIFO submission function. Every addition must have one matching
memcompress_reclaim_complete(), including failures. A success cursor can
briefly precede the final partial-batch physical free and is an allocation
retry hint, not a guarantee that a particular allocation can succeed.

Lifecycle and limits
====================

Contexts are allocated separately from pglist_data to preserve its layout.
All tasks are created before being started. Startup waits until every worker
has entered its function before publishing the context, so a concurrent stop
cannot bypass all queue-draining functions. Explicit task references protect
workers that finish drainage before their individual stop/join call.
Allocation or creation failure leaves synchronous reclaim available.

Stopping first joins kswapd, then marks the queue stopping and wakes all wait
queues. Workers finish queued items and local batches before exiting; only
after every worker is joined are the FIFO and context released. Workers are
not freezable while they own locked folios. The task-reference and startup
handshake protections are native lifetime safeguards, not claims about the
vendor's internal structure layout.

Matching this scheduling policy does not establish complete vendor parity.
Grouped fault-in, packed writeback/drain, allocator and codec differences need
separate work. Virtual-machine tests can validate execution and data integrity;
phone latency, energy use, memory-hotplug failure paths and vendor/native
performance equivalence require their own measurements.

Reproducing the QEMU functional checks
=====================================

Kswapd still scans the LRUs and decides how much to reclaim. Kreclaimd handles
eligible work selected by that scan; clean file-cache reclaim and other normal
paths remain available. An allocating task can also enter direct reclaim.
Growing compression statistics or the presence of worker names alone does not
establish that background reclamation and subsequent data recovery succeeded.

The companion memc research checkout provides ``validation/memcompress_qemu.py``
and its static guest init. Its Chinese operator manual, ``validation/QEMU.md``,
covers tool preparation, kernel builds, raw QEMU arguments, report interpretation
and troubleshooting. The following assumes that checkout is at
``$HOME/project/memc`` and this kernel is at ``$HOME/kernel_workspace/op13``.
Adjust those paths and the QEMU executable for another workspace.

Use a completed ARM64 4 KiB Image with memcompress enabled. The minimal guest
needs built-in PL011 console, GIC, PSCI, initramfs/gzip, procfs and sysfs support.
The writeback case also needs built-in PCI host and virtio PCI block support.
No modules or Android userspace are included in this initramfs. On an x86 host,
TCG emulates ARM64 without requiring KVM or root privileges.

Prepare an immutable input copy and compile the existing selftest::

    mkdir -p "$HOME/.tmp"
    export TMPDIR="$HOME/.tmp"
    export MEMC_RUN="$(mktemp -d "$TMPDIR/memc-qemu.XXXXXX")"
    export MEMC_KERNEL="$HOME/kernel_workspace/op13"
    export MEMC_QEMU="$HOME/.tmp/memcompress-qemu/qemu-system-aarch64"
    cp "$MEMC_KERNEL/out/arch/arm64/boot/Image" "$MEMC_RUN/Image"
    aarch64-linux-gnu-gcc -O2 -static -Wall -Wextra -Werror \
      "$MEMC_KERNEL/tools/testing/selftests/mm/memcompress.c" \
      -o "$MEMC_RUN/memcompress-selftest"
    cd "$HOME/project/memc"

Run the background compression case::

    python3 validation/memcompress_qemu.py \
      --qemu "$MEMC_QEMU" --kernel "$MEMC_RUN/Image" \
      --selftest "$MEMC_RUN/memcompress-selftest" \
      --mode compression --cpus 8 --memory-mib 1024 --timeout 600 \
      --output "$MEMC_RUN/compression-8cpu"

Repeat with ``--cpus 2`` and a new output directory to check the single regular
worker topology. Use ``--mode writeback`` with eight CPUs and another new output
directory to exercise ordinary swap: the runner creates a private regular-file
virtual disk, and the guest enables that swap and disables memcompress after
its initial compression selftests. Swapoff must succeed after data verification.
No host block device, phone, shared filesystem or network is exposed to the guest.

The runner builds its own initramfs, records input/source hashes and tool versions,
and saves ``serial.log`` and ``report.json`` in the output directory. Output
directories must not already exist. ``--prepare-only`` checks compilation and
packing without booting; its report has status ``prepared``, not ``pass``.
For a real run, require a zero runner exit code and report status ``pass``.
Check the unskipped selftests, data-verification count, warnings, fatal messages
and per-worker scheduler deltas. The aggregate worker-runtime check does not
require every worker to run; inspect the burst worker separately.

This workload raises the guest's min_free_kbytes to 65536, checks a 48 MiB
MemFree floor between 4 MiB allocation batches, and caps the allocation at
1.25 times MemTotal. The allocation stage, pressure child and host runner have
separate time limits. It verifies every 64-bit word on fault-in. These guest
settings deliberately trigger background reclaim and are not stock-policy
performance measurements. Pressure mappings use MADV_NOHUGEPAGE and 4 KiB pages;
async multi-page folios, failure injection and node removal need other tests.
QEMU Cortex-A76 has no MTE, so configured HW_TAGS does not establish runtime
hardware-tag sanitizer coverage. Keep virtual-machine functionality evidence
separate from phone stability, foreground latency and energy measurements.
