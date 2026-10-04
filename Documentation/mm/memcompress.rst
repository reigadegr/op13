.. SPDX-License-Identifier: GPL-2.0

============================
Memcompress reclaim behavior
============================

Memcompress stores anonymous memory in a compressed RAM pool and represents
the displaced mappings with reserved swap-type tokens. It needs the swap
infrastructure enabled by CONFIG_SWAP; an active ordinary swap device is
not required for this RAM-backed path.

Execution and accounting
========================

The current reclaim integration in shrink_folio_list() performs compression
synchronously. Background reclaim leases a context and stores the folio in
kswapd; direct reclaim performs that work in the reclaiming task. Compression
contexts are reusable codec resources, not dedicated kernel threads.

memcompress_reclaim_queue() adds the number of base pages to per-node
inflight accounting. It neither enqueues a folio nor schedules work. Every
such addition must have one matching memcompress_reclaim_complete() call
with the original page count, including failure paths. Only successful
completions advance the progress cursor; both outcomes reduce inflight.

The progress wait helper can return because work drained without success,
or because a fatal signal is pending. Callers that need proof of successful
reclaim must compare the progress cursor again. A successful completion can
precede the final batched physical free, so it is not a guarantee that a
particular allocation can already succeed.

Vendor worker differences
=========================

This tree does not create the vendor kreclaimd<N>/<index> tasks. The WORKER
and BURST reclaim-source enum values describe context-admission classes;
their presence does not implement worker tasks or asynchronous reclaim.

The examined vendor implementation creates a shared FIFO for memcompress
and writepage work. With eight online CPUs at startup it creates six regular
workers and one burst worker. The suffix is a worker index, not a CPU number;
the entry path allows execution on the online CPU mask. A burst request,
queue-depth throttling and successful-page feedback coordinate those tasks
with kswapd. These mechanisms are absent from the current synchronous port.
The direct-reclaim contention feedback at the vmscan call sites is also not
implemented here.

An asynchronous port must transfer folio references, locks and LRU ownership
only after a successful enqueue, retain synchronous fallback on rejection,
and preserve anon_vma lifetime for failed-store PTE restoration. Startup
failure and shutdown must release or drain all transferred ownership.
Successful pages must be attributed exactly once: adding worker completion
counts while retaining synchronous attribution would double count reclaim.
Queue item counts and inflight base-page counts are different units.

Kernel compilation and store/fault tests alone cannot establish equivalent
reclaim scheduling, foreground latency, power use or failure behavior.
