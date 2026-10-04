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
