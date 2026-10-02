// SPDX-License-Identifier: GPL-2.0
/*
 * Anonymous memory compression restored from the vendor implementation.
 *
 * The token, same-fill, classifier and payload paths follow the recovered
 * implementation. Native MM helpers replace vendor layout offsets. Storage
 * rejected here remains eligible for the kernel's ordinary swap path; packed
 * swap writeback and its workers are deliberately not implemented here.
 */
#define pr_fmt(fmt) "memcompress: " fmt

#include <linux/atomic.h>
#include <linux/bitmap.h>
#include <linux/cpu.h>
#include <linux/crypto.h>
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/kref.h>
#include <linux/local_lock.h>
#include <linux/memcompress.h>
#include <linux/memcontrol.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/pagemap.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/topology.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/zpool.h>
#include <linux/zsmalloc.h>

#include <asm/mte.h>

#define MC_MAX_CONTEXTS 32U

enum memcompress_state {
	MC_PENDING,
	MC_SAMEFILL,
	MC_STORED,
};

struct memcompress_entry {
	struct rcu_head rcu;
	struct kref refcount;
	struct mutex lock;
	struct folio *folio;
	struct obj_cgroup *objcg;
	unsigned long handle;
	u32 token;
	u32 length;
	u32 charged_bytes;
	u8 nr_pages;
	u8 page_idx;
	u8 state;
	bool folio_owner;
	bool refresh_pending;
};

struct memcompress_reclaim_ctx {
	struct crypto_comp *tfm;
	u8 *dst;
	u32 shadow_seq;
	bool shadow_enabled;
	bool borrowed;
	bool background;
};

struct memcompress_decomp_ctx {
	local_lock_t lock;
	struct crypto_comp *tfm;
};

struct memcompress_payload {
	unsigned long handle;
	unsigned int length;
};

struct memcompress_reclaim_node {
	atomic_long_t inflight;
	atomic64_t success;
	wait_queue_head_t wait;
};

static DEFINE_XARRAY_ALLOC(memcompress_entries);
static DEFINE_MUTEX(memcompress_token_lock);
static DEFINE_SPINLOCK(memcompress_context_lock);
static DECLARE_WAIT_QUEUE_HEAD(memcompress_context_wait);
static DEFINE_PER_CPU(struct memcompress_decomp_ctx, memcompress_decomp_ctxs);
static struct memcompress_reclaim_ctx memcompress_contexts[MC_MAX_CONTEXTS];
static struct memcompress_reclaim_node memcompress_nodes[MAX_NUMNODES];
static struct kmem_cache *memcompress_entry_cache;
static struct zpool *memcompress_pool;
static unsigned int memcompress_nr_contexts;
static unsigned long memcompress_context_all;
static unsigned long memcompress_context_free;
static unsigned long memcompress_context_foreground;
static unsigned int memcompress_borrowed;
static unsigned int memcompress_borrow_limit;
static unsigned int memcompress_background_waiters;
static unsigned int memcompress_background_active;
static u32 memcompress_token_cursor = 1;
static bool memcompress_enabled;
static bool memcompress_enabled_user_set;
static bool memcompress_auto_enable = true;
static bool memcompress_compressor_user_set;
static unsigned int memcompress_capacity_threshold = 200;
static char memcompress_compressor[CRYPTO_MAX_ALG_NAME] = "zstd";
static char memcompress_zpool_type[32] = "zsmalloc";
static atomic_long_t memcompress_stored_bytes;
static atomic_long_t memcompress_compressed_bytes;
static atomic_long_t memcompress_same_filled_pages;
static atomic64_t memcompress_classifier_calls;
static atomic64_t memcompress_classifier_bypasses;

module_param_named(auto_enable, memcompress_auto_enable, bool, 0444);
module_param_named(capacity_threshold, memcompress_capacity_threshold, uint, 0644);

static int memcompress_compressor_set(const char *value,
				     const struct kernel_param *kp)
{
	int ret;

	if (memcompress_nr_contexts)
		return -EBUSY;
	ret = param_set_copystring(value, kp);
	if (!ret)
		memcompress_compressor_user_set = true;
	return ret;
}

static const struct kernel_param_ops memcompress_compressor_ops = {
	.set = memcompress_compressor_set,
	.get = param_get_string,
};

static struct kparam_string memcompress_compressor_param = {
	.maxlen = sizeof(memcompress_compressor),
	.string = memcompress_compressor,
};

module_param_cb(compressor, &memcompress_compressor_ops,
		&memcompress_compressor_param, 0444);

static void memcompress_auto_enable_work(struct work_struct *work)
{
	unsigned long flags;

	spin_lock_irqsave(&memcompress_context_lock, flags);
	if (memcompress_auto_enable && !READ_ONCE(memcompress_enabled_user_set)) {
		/* Publish backend initialization before reclaim can enter it. */
		smp_store_release(&memcompress_enabled, true);
	}
	spin_unlock_irqrestore(&memcompress_context_lock, flags);
	wake_up_all(&memcompress_context_wait);
}

static DECLARE_DELAYED_WORK(memcompress_auto_enable_worker,
			    memcompress_auto_enable_work);

static int memcompress_entry_charge(struct memcompress_entry *entry, size_t size)
{
#ifdef CONFIG_MEMCG_KMEM
	int ret;

	if (!entry->objcg || !size)
		return 0;
	ret = obj_cgroup_charge(entry->objcg,
			       GFP_NOWAIT | __GFP_NOMEMALLOC | __GFP_NOWARN, size);
	if (ret)
		return ret;
	entry->charged_bytes += size;
#endif
	return 0;
}

static void memcompress_entry_uncharge(struct memcompress_entry *entry, size_t size)
{
#ifdef CONFIG_MEMCG_KMEM
	if (!entry->objcg || !size)
		return;
	obj_cgroup_uncharge(entry->objcg, size);
	entry->charged_bytes -= size;
#endif
}

static void memcompress_entry_account_put(struct memcompress_entry *entry)
{
#ifdef CONFIG_MEMCG_KMEM
	if (!entry->objcg)
		return;
	memcompress_entry_uncharge(entry, entry->charged_bytes);
	obj_cgroup_put(entry->objcg);
	entry->objcg = NULL;
#endif
}

static void memcompress_entry_free_unpublished(struct memcompress_entry *entry)
{
	memcompress_entry_account_put(entry);
	kmem_cache_free(memcompress_entry_cache, entry);
}

static const u16 memcompress_log2_frac_milli[16] = {
	0, 87, 170, 248, 322, 392, 459, 523,
	585, 644, 700, 755, 807, 858, 907, 954,
};

bool memcompress_available(void)
{
	/* Pairs with enable's publication of the initialized backend. */
	return smp_load_acquire(&memcompress_enabled) && memcompress_nr_contexts;
}

bool is_memcompress_shadow(void *shadow)
{
	swp_entry_t entry;

	if (!xa_is_value(shadow))
		return false;
	entry.val = xa_to_value(shadow);
	return is_memcompress_entry(entry);
}

unsigned long memcompress_shadow_token(void *shadow)
{
	swp_entry_t entry = { .val = xa_to_value(shadow) };

	return swp_offset(entry);
}

struct memcompress_entry *memcompress_get_entry(unsigned long token)
{
	struct memcompress_entry *entry;

	if (!token || token > U32_MAX)
		return NULL;
	rcu_read_lock();
	entry = xa_load(&memcompress_entries, token);
	if (!entry || !kref_get_unless_zero(&entry->refcount))
		entry = NULL;
	rcu_read_unlock();
	return entry;
}

bool memcompress_entry_get(unsigned long token)
{
	return memcompress_get_entry(token) != NULL;
}

bool memcompress_entry_present(unsigned long token)
{
	bool present;

	rcu_read_lock();
	present = xa_load(&memcompress_entries, token) != NULL;
	rcu_read_unlock();
	return present;
}

static void memcompress_entry_rcu_free(struct rcu_head *rcu)
{
	struct memcompress_entry *entry;

	entry = container_of(rcu, struct memcompress_entry, rcu);
	kmem_cache_free(memcompress_entry_cache, entry);
}

/* PTE invalidation calls this with a page-table spinlock held. */
static void memcompress_entry_release(struct kref *ref)
{
	struct memcompress_entry *entry;

	entry = container_of(ref, struct memcompress_entry, refcount);
	if (entry->state == MC_STORED)
		zpool_free(memcompress_pool, entry->handle);
	if (entry->state == MC_SAMEFILL)
		atomic_long_dec(&memcompress_same_filled_pages);
	if (entry->folio)
		folio_put(entry->folio);
	if (system_supports_mte())
		mte_invalidate_tags(SWP_MEMCOMPRESS, entry->token);
	memcompress_entry_account_put(entry);
	atomic_long_sub(PAGE_SIZE, &memcompress_stored_bytes);
	atomic_long_sub(entry->length, &memcompress_compressed_bytes);
	/* Keep the token reserved until all metadata keyed by it is gone. */
	xa_erase(&memcompress_entries, entry->token);
	call_rcu(&entry->rcu, memcompress_entry_rcu_free);
}

void memcompress_entry_put(struct memcompress_entry *entry)
{
	if (entry)
		kref_put(&entry->refcount, memcompress_entry_release);
}

void memcompress_invalidate(unsigned long token)
{
	struct memcompress_entry *entry = memcompress_get_entry(token);

	if (entry) {
		memcompress_entry_put(entry);
		memcompress_entry_put(entry);
	}
}

void memcompress_invalidate_nr(unsigned long token, unsigned int nr_pages)
{
	unsigned int i;

	if (!token || token > U32_MAX || nr_pages > U32_MAX - token + 1)
		return;
	for (i = 0; i < nr_pages; i++)
		memcompress_invalidate(token + i);
}

unsigned int memcompress_entry_nr_pages(unsigned long token,
				       unsigned long *base_token)
{
	struct memcompress_entry *entry = memcompress_get_entry(token);
	unsigned int nr_pages = 1;

	if (base_token)
		*base_token = token;
	if (!entry)
		return 1;
	if (entry->nr_pages && entry->nr_pages <= MEMCOMPRESS_MAX_FOLIO_PAGES &&
	    entry->page_idx < entry->nr_pages && token > entry->page_idx &&
	    token - entry->page_idx <= U32_MAX - entry->nr_pages + 1) {
		nr_pages = entry->nr_pages;
		if (base_token)
			*base_token = token - entry->page_idx;
	}
	memcompress_entry_put(entry);
	return nr_pages;
}

bool memcompress_entry_stat(unsigned long token, unsigned long *compressed,
			   int *mapcount)
{
	struct memcompress_entry *entry;
	int refs;

	if (compressed)
		*compressed = 0;
	if (mapcount)
		*mapcount = 0;
	entry = memcompress_get_entry(token);
	if (!entry)
		return false;
	refs = refcount_read(&entry->refcount.refcount);
	if (compressed)
		*compressed = READ_ONCE(entry->length);
	if (mapcount)
		*mapcount = max(refs - 1 - READ_ONCE(entry->folio_owner), 1);
	memcompress_entry_put(entry);
	return true;
}

bool memcompress_entry_set_refresh_pending(unsigned long token)
{
	struct memcompress_entry *entry = memcompress_get_entry(token);
	bool old;

	if (!entry)
		return false;
	mutex_lock(&entry->lock);
	old = entry->refresh_pending;
	entry->refresh_pending = true;
	mutex_unlock(&entry->lock);
	memcompress_entry_put(entry);
	return !old;
}

void memcompress_entry_clear_refresh_pending(unsigned long token)
{
	struct memcompress_entry *entry = memcompress_get_entry(token);

	if (!entry)
		return;
	mutex_lock(&entry->lock);
	entry->refresh_pending = false;
	mutex_unlock(&entry->lock);
	memcompress_entry_put(entry);
}

unsigned int memcompress_pte_batch(pte_t *ptep, unsigned int max_nr)
{
	swp_entry_t first, entry;
	pte_t pte;
	unsigned int i;

	if (!max_nr)
		return 0;
	pte = ptep_get(ptep);
	if (!is_swap_pte(pte))
		return 0;
	first = pte_to_swp_entry(pte);
	if (!is_memcompress_entry(first))
		return 0;
	for (i = 0; i < max_nr; i++) {
		pte_t next = ptep_get(ptep + i);

		if (!is_swap_pte(next) ||
		    pte_swp_exclusive(next) != pte_swp_exclusive(pte))
			break;
		entry = pte_to_swp_entry(next);
		if (!is_memcompress_entry(entry) ||
		    swp_offset(entry) != swp_offset(first) + i)
			break;
	}
	return i;
}

static bool memcompress_same_fill(const u64 *src)
{
	u64 value = src[0];
	unsigned int i;

	for (i = 1; i < PAGE_SIZE / sizeof(*src); i++)
		if (src[i] != value)
			return false;
	return true;
}

static bool memcompress_shadow_repeated(const u8 *src, unsigned int phase)
{
	u32 table[128] = {};
	unsigned int i;

	for (i = 0; i < 64; i++) {
		const u32 *words = (const u32 *)(src + phase * 8 + i * 64);
		u32 fingerprint = (words[0] ^ words[1]) | 1;
		u32 slot = (fingerprint * 0x9e3779b1U) >> 25;

		while (table[slot]) {
			if (table[slot] == fingerprint)
				return true;
			slot = (slot + 1) & 127;
		}
		table[slot] = fingerprint;
	}
	return false;
}

static u32 memcompress_log2_milli(u32 value)
{
	unsigned int msb = fls(value) - 1;
	u32 frac = ((value << 4) >> msb) & 15;

	return msb * 1000 + memcompress_log2_frac_milli[frac];
}

static u16 memcompress_shadow_entropy(const u8 *src, unsigned int phase)
{
	u16 histogram[256] = {};
	u64 sum = 0;
	unsigned int i, b;

	for (i = 0; i < 64; i++) {
		u64 sample = *(const u64 *)(src + phase * 8 + i * 64);

		for (b = 0; b < 8; b++)
			histogram[(sample >> (b * 8)) & 255]++;
	}
	for (i = 0; i < 256; i++)
		if (histogram[i] > 1)
			sum += (u64)memcompress_log2_milli(histogram[i]) * histogram[i];
	return 9000 - (u16)(sum >> 9);
}

static bool memcompress_classifier_bypass(const u8 *src,
					struct memcompress_reclaim_ctx *ctx)
{
	u32 calls = ++ctx->shadow_seq;
	unsigned int phase = (calls * 0x61c88647U) >> 29;
	u16 first, second;

	atomic64_inc(&memcompress_classifier_calls);
	if (memcompress_shadow_repeated(src, phase))
		return false;
	first = memcompress_shadow_entropy(src, phase);
	if (first < 7400)
		return false;
	phase ^= 4;
	if (memcompress_shadow_repeated(src, phase))
		return false;
	second = memcompress_shadow_entropy(src, phase);
	if (!(calls % 64) || min(first, second) < 7400)
		return false;
	atomic64_inc(&memcompress_classifier_bypasses);
	return true;
}

static struct memcompress_reclaim_ctx *
memcompress_context_get(enum memcompress_reclaim_source source, bool best_effort)
{
	struct memcompress_reclaim_ctx *ctx;
	unsigned long flags, available, mask;
	bool background = source != MEMCOMPRESS_RECLAIM_DIRECT;
	bool borrowed;
	unsigned int idx, background_limit;

	if (!memcompress_available() || source >= MEMCOMPRESS_RECLAIM_SOURCE_NR)
		return NULL;
	for (;;) {
		spin_lock_irqsave(&memcompress_context_lock, flags);
		if (!memcompress_available()) {
			spin_unlock_irqrestore(&memcompress_context_lock, flags);
			return NULL;
		}
		background_limit = min(max(num_online_cpus(), 2U) - 1,
				       memcompress_nr_contexts);
		mask = background ? memcompress_context_all :
			memcompress_context_foreground;
		available = memcompress_context_free & mask;
		if (background &&
		    memcompress_background_active >= background_limit)
			available = 0;
		borrowed = false;
		if (!available && !background && !best_effort &&
		    !memcompress_background_waiters &&
		    memcompress_borrowed < memcompress_borrow_limit) {
			available = memcompress_context_free &
				~memcompress_context_foreground;
			borrowed = available != 0;
		}
		if (available) {
			idx = __ffs(available);
			memcompress_context_free &= ~BIT(idx);
			memcompress_borrowed += borrowed;
			memcompress_background_active += background;
			ctx = &memcompress_contexts[idx];
			ctx->borrowed = borrowed;
			ctx->background = background;
			ctx->shadow_enabled = false;
			spin_unlock_irqrestore(&memcompress_context_lock, flags);
			return ctx;
		}
		if (!background || best_effort || !memcompress_available()) {
			spin_unlock_irqrestore(&memcompress_context_lock, flags);
			return NULL;
		}
		memcompress_background_waiters++;
		spin_unlock_irqrestore(&memcompress_context_lock, flags);
		wait_event(memcompress_context_wait,
			   (READ_ONCE(memcompress_context_free) &&
			    READ_ONCE(memcompress_background_active) <
			    min(max(num_online_cpus(), 2U) - 1,
				memcompress_nr_contexts)) ||
			   !memcompress_available());
		spin_lock_irqsave(&memcompress_context_lock, flags);
		memcompress_background_waiters--;
		spin_unlock_irqrestore(&memcompress_context_lock, flags);
	}
}

bool memcompress_reclaim_ctx_precheck(unsigned int nr_pages,
				     enum memcompress_reclaim_source source)
{
	unsigned long flags;
	bool available;

	if (!memcompress_available() || !nr_pages ||
	    nr_pages > MEMCOMPRESS_MAX_FOLIO_PAGES ||
	    source >= MEMCOMPRESS_RECLAIM_SOURCE_NR)
		return false;
	if (source != MEMCOMPRESS_RECLAIM_DIRECT)
		return true;
	spin_lock_irqsave(&memcompress_context_lock, flags);
	available = memcompress_context_free & memcompress_context_foreground;
	if (!available && !memcompress_background_waiters &&
	    memcompress_borrowed < memcompress_borrow_limit)
		available = memcompress_context_free & ~memcompress_context_foreground;
	spin_unlock_irqrestore(&memcompress_context_lock, flags);
	return available;
}

struct memcompress_reclaim_ctx *
memcompress_reclaim_ctx_get(unsigned int nr_pages,
			   enum memcompress_reclaim_source source)
{
	struct memcompress_reclaim_ctx *ctx;
	const char *name;

	if (!nr_pages || nr_pages > MEMCOMPRESS_MAX_FOLIO_PAGES)
		return NULL;
	ctx = memcompress_context_get(source, false);
	if (!ctx)
		return NULL;
	name = crypto_tfm_alg_driver_name(crypto_comp_tfm(ctx->tfm));
	ctx->shadow_enabled = PAGE_SIZE == 4096 && nr_pages == 1 &&
		source == MEMCOMPRESS_RECLAIM_DIRECT &&
		(!strcmp(name, "zstd-generic") || !strcmp(name, "zstdp-generic"));
	return ctx;
}

void memcompress_reclaim_ctx_put(struct memcompress_reclaim_ctx *ctx)
{
	unsigned long flags;
	unsigned int idx;

	if (!ctx)
		return;
	idx = ctx - memcompress_contexts;
	if (WARN_ON_ONCE(idx >= memcompress_nr_contexts))
		return;
	spin_lock_irqsave(&memcompress_context_lock, flags);
	if (WARN_ON_ONCE(memcompress_context_free & BIT(idx))) {
		spin_unlock_irqrestore(&memcompress_context_lock, flags);
		return;
	}
	memcompress_borrowed -= ctx->borrowed;
	memcompress_background_active -= ctx->background;
	ctx->borrowed = false;
	memcompress_context_free |= BIT(idx);
	spin_unlock_irqrestore(&memcompress_context_lock, flags);
	wake_up_all(&memcompress_context_wait);
}

static int memcompress_prepare_payload(struct memcompress_reclaim_ctx *ctx,
				      const void *src, bool multi_page,
				      struct memcompress_payload *payload)
{
	unsigned int length = PAGE_SIZE * 2;
	unsigned int huge_class = zs_huge_class_size(NULL);
	gfp_t gfp = GFP_NOWAIT | __GFP_NOWARN | __GFP_NORETRY;
	const void *data;
	void *mapped;
	int ret;

	if (memcompress_same_fill(src)) {
		payload->handle = *(const u64 *)src;
		payload->length = 0;
		return 0;
	}
	if (!multi_page && ctx->shadow_enabled &&
	    memcompress_classifier_bypass(src, ctx))
		return -E2BIG;
	ret = crypto_comp_compress(ctx->tfm, src, PAGE_SIZE, ctx->dst, &length);
	if (ret)
		return ret;
	/* zsmalloc's huge-class query is global and does not inspect its pool. */
	if (length >= PAGE_SIZE || (huge_class && length >= huge_class)) {
		if (!multi_page)
			return -E2BIG;
		length = PAGE_SIZE;
		data = src;
	} else {
		data = ctx->dst;
	}
	ret = zpool_malloc(memcompress_pool, length, gfp, &payload->handle);
	if (ret && ctx->background)
		ret = zpool_malloc(memcompress_pool, length,
				   GFP_NOIO | __GFP_NOWARN | __GFP_NORETRY,
				   &payload->handle);
	if (ret)
		return ret;
	mapped = zpool_map_handle(memcompress_pool, payload->handle, ZPOOL_MM_WO);
	if (!mapped) {
		zpool_free(memcompress_pool, payload->handle);
		return -EIO;
	}
	memcpy(mapped, data, length);
	zpool_unmap_handle(memcompress_pool, payload->handle);
	payload->length = length;
	return 0;
}

static struct memcompress_entry *memcompress_entry_alloc(struct folio *folio)
{
	struct memcompress_entry *entry;

	entry = kmem_cache_zalloc(memcompress_entry_cache,
				 GFP_NOWAIT | __GFP_NOWARN);
	if (!entry)
		return NULL;
	mutex_init(&entry->lock);
	kref_init(&entry->refcount);
	entry->objcg = get_obj_cgroup_from_folio(folio);
#ifdef CONFIG_MEMCG
	if (!entry->objcg && !mem_cgroup_disabled()) {
		struct mem_cgroup *memcg = folio_memcg(folio);

		/* Without objcg accounting, retain non-root pages as resident. */
		if (memcg && !mem_cgroup_is_root(memcg)) {
			memcompress_entry_free_unpublished(entry);
			return NULL;
		}
	}
#endif
	if (memcompress_entry_charge(entry, sizeof(*entry))) {
		memcompress_entry_free_unpublished(entry);
		return NULL;
	}
	return entry;
}

static int memcompress_alloc_tokens(u32 *tokens, unsigned int nr_pages)
{
	u32 start, max = U32_MAX - nr_pages + 1;
	unsigned int i;
	int ret;
	bool wrapped = false;

	mutex_lock(&memcompress_token_lock);
	start = memcompress_token_cursor;
	if (!start || start > max)
		start = 1;
retry:
	ret = xa_alloc(&memcompress_entries, &tokens[0], NULL,
		       XA_LIMIT(start, max), GFP_NOWAIT | __GFP_NOWARN);
	if (ret) {
		if (ret == -EBUSY && !wrapped && start != 1) {
			start = 1;
			wrapped = true;
			goto retry;
		}
		goto out;
	}
	for (i = 1; i < nr_pages; i++) {
		tokens[i] = tokens[0] + i;
		ret = xa_insert(&memcompress_entries, tokens[i], NULL,
				GFP_NOWAIT | __GFP_NOWARN);
		if (ret)
			break;
	}
	if (ret) {
		u32 collision = tokens[i];

		while (i--)
			xa_erase(&memcompress_entries, tokens[i]);
		if (ret == -EBUSY && collision < max) {
			start = collision + 1;
			goto retry;
		}
		if (ret == -EBUSY && !wrapped) {
			start = 1;
			wrapped = true;
			goto retry;
		}
		goto out;
	}
	memcompress_token_cursor = tokens[0] + nr_pages;
out:
	mutex_unlock(&memcompress_token_lock);
	return ret;
}

bool memcompress_reserve_eligible(struct folio *folio)
{
	unsigned int nr_pages = folio_nr_pages(folio);

	return memcompress_available() && nr_pages <= MEMCOMPRESS_MAX_FOLIO_PAGES &&
		folio_test_locked(folio) && folio_test_anon(folio) &&
		!folio_test_ksm(folio) &&
		folio_test_swapbacked(folio) && !folio_test_mlocked(folio) &&
		!folio_test_swapcache(folio) && !folio_mapping(folio);
}

bool memcompress_fresh_reservation(struct folio *folio)
{
	return memcompress_reserve_eligible(folio) &&
		!memcompress_folio_token(folio) && !folio_get_private(folio);
}

bool memcompress_reserve(struct folio *folio, bool *stored)
{
	struct memcompress_entry *entries[MEMCOMPRESS_MAX_FOLIO_PAGES] = {};
	u32 tokens[MEMCOMPRESS_MAX_FOLIO_PAGES] = {};
	unsigned int nr_pages = folio_nr_pages(folio), i;
	unsigned long base = memcompress_folio_token(folio);
	bool ret = false;

	if (stored)
		*stored = false;
	if (!memcompress_reserve_eligible(folio))
		return false;
	if (base) {
		for (i = 0; i < nr_pages; i++) {
			struct memcompress_entry *entry = memcompress_get_entry(base + i);
			bool matches;

			if (!entry)
				return false;
			mutex_lock(&entry->lock);
			matches = entry->folio == folio && entry->folio_owner &&
				entry->nr_pages == nr_pages && entry->page_idx == i;
			mutex_unlock(&entry->lock);
			memcompress_entry_put(entry);
			if (!matches)
				return false;
		}
		return true;
	}
	if (folio_get_private(folio))
		return false;
	if (!memcompress_available())
		goto out;
	for (i = 0; i < nr_pages; i++) {
		entries[i] = memcompress_entry_alloc(folio);
		if (!entries[i])
			goto free_entries;
	}
	if (memcompress_alloc_tokens(tokens, nr_pages))
		goto free_entries;
	for (i = 0; i < nr_pages; i++) {
		struct memcompress_entry *entry = entries[i];

		entry->token = tokens[i];
		entry->nr_pages = nr_pages;
		entry->page_idx = i;
		entry->folio = folio;
		entry->folio_owner = true;
		entry->state = MC_PENDING;
		folio_get(folio);
		atomic_long_add(PAGE_SIZE, &memcompress_stored_bytes);
	}
	for (i = 0; i < nr_pages; i++) {
		void *old = xa_store(&memcompress_entries, tokens[i], entries[i],
				     GFP_NOWAIT);

		if (WARN_ON_ONCE(xa_is_err(old))) {
			unsigned int j;

			for (j = 0; j < nr_pages; j++)
				memcompress_entry_put(entries[j]);
			goto out;
		}
	}
	folio->private = (void *)swp_entry(SWP_MEMCOMPRESS, tokens[0]).val;
	ret = true;
	goto out;
free_entries:
	for (i = 0; i < nr_pages; i++)
		if (entries[i])
			memcompress_entry_free_unpublished(entries[i]);
out:
	return ret;
}

bool memcompress_store_cache(struct folio *folio, unsigned long *token)
{
	struct memcompress_reclaim_ctx *ctx = NULL;
	struct memcompress_entry *entry = NULL;
	struct memcompress_payload payload = {};
	const void *src;
	u32 id;
	bool ret = false;

	if (!token)
		return false;
	*token = 0;
	if (!memcompress_fresh_reservation(folio) || folio_test_large(folio) ||
	    folio_mapped(folio))
		return false;
	/* Order the unmapped-PTE check against GUP's reference acquisition. */
	smp_mb();
	if (folio_ref_count(folio) != 1)
		return false;
	src = page_address(folio_page(folio, 0));
	if (!src)
		return false;
	if (!memcompress_available())
		goto out;
	entry = memcompress_entry_alloc(folio);
	if (!entry)
		goto out;
	if (memcompress_same_fill(src)) {
		payload.handle = *(const u64 *)src;
	} else {
		ctx = memcompress_context_get(MEMCOMPRESS_RECLAIM_DIRECT, true);
		if (!ctx || memcompress_prepare_payload(ctx, src, false, &payload))
			goto free_entry;
	}
	if (memcompress_entry_charge(entry, payload.length))
		goto free_payload;
	if (memcompress_alloc_tokens(&id, 1))
		goto free_payload;
	entry->token = id;
	entry->nr_pages = 1;
	entry->handle = payload.handle;
	entry->length = payload.length;
	entry->state = payload.length ? MC_STORED : MC_SAMEFILL;
	atomic_long_add(PAGE_SIZE, &memcompress_stored_bytes);
	atomic_long_add(payload.length, &memcompress_compressed_bytes);
	if (!payload.length)
		atomic_long_inc(&memcompress_same_filled_pages);
	if (WARN_ON_ONCE(xa_is_err(xa_store(&memcompress_entries, id, entry,
					   GFP_NOWAIT)))) {
		memcompress_entry_put(entry);
		goto out;
	}
	folio->private = (void *)swp_entry(SWP_MEMCOMPRESS, id).val;
	if (arch_prepare_to_swap(folio)) {
		folio->private = 0;
		memcompress_entry_put(entry);
		goto out;
	}
	folio->private = 0;
	*token = id;
	ret = true;
	goto out;
free_payload:
	if (payload.length)
		zpool_free(memcompress_pool, payload.handle);
free_entry:
	memcompress_entry_free_unpublished(entry);
out:
	memcompress_reclaim_ctx_put(ctx);
	return ret;
}

bool memcompress_store_after_unmap(struct folio *folio,
				  struct memcompress_reclaim_ctx **ctxp)
{
	struct memcompress_entry *entries[MEMCOMPRESS_MAX_FOLIO_PAGES] = {};
	struct memcompress_payload payload[MEMCOMPRESS_MAX_FOLIO_PAGES] = {};
	struct memcompress_reclaim_ctx *ctx;
	unsigned long base = memcompress_folio_token(folio);
	unsigned int nr_pages = folio_nr_pages(folio), i;
	unsigned int nr_charged = 0;
	u64 total_length = 0;
	bool raw = false, ret = false;

	if (!ctxp || !*ctxp)
		return false;
	ctx = *ctxp;
	*ctxp = NULL;
	if (!memcompress_reserve_eligible(folio) || folio_mapped(folio) || !base ||
	    folio_maybe_dma_pinned(folio))
		goto put_ctx;
	for (i = 0; i < nr_pages; i++) {
		struct memcompress_entry *entry = memcompress_get_entry(base + i);
		bool matches;

		entries[i] = entry;
		if (!entry)
			goto free_payload;
		mutex_lock(&entry->lock);
		matches = entry->folio == folio && entry->folio_owner &&
			entry->state == MC_PENDING && entry->nr_pages == nr_pages &&
			entry->page_idx == i;
		mutex_unlock(&entry->lock);
		if (!matches)
			goto free_payload;
	}
	/* Only the isolator and each reservation may still own physical refs. */
	smp_mb();
	if (folio_ref_count(folio) != 1 + nr_pages)
		goto free_payload;
	for (i = 0; i < nr_pages; i++) {
		const void *src = page_address(folio_page(folio, i));

		if (!src || memcompress_prepare_payload(ctx, src, nr_pages != 1,
						       &payload[i]))
			goto free_payload;
		total_length += payload[i].length;
		raw |= payload[i].length == PAGE_SIZE;
	}
	if (raw && total_length > (u64)(nr_pages - 1) * PAGE_SIZE)
		goto free_payload;
	/* Charge every member before making any compressed payload visible. */
	for (i = 0; i < nr_pages; i++) {
		if (memcompress_entry_charge(entries[i], payload[i].length))
			goto uncharge_payload;
		nr_charged++;
	}
	if (arch_prepare_to_swap(folio))
		goto uncharge_payload;
	for (i = 0; i < nr_pages; i++) {
		struct memcompress_entry *entry = entries[i];

		mutex_lock(&entry->lock);
		entry->handle = payload[i].handle;
		entry->length = payload[i].length;
		entry->state = payload[i].length ? MC_STORED : MC_SAMEFILL;
		entry->folio = NULL;
		entry->folio_owner = false;
		atomic_long_add(entry->length, &memcompress_compressed_bytes);
		if (!entry->length)
			atomic_long_inc(&memcompress_same_filled_pages);
		mutex_unlock(&entry->lock);
		folio_put(folio);
		memcompress_entry_put(entry);
	}
	folio->private = 0;
	ret = true;
	goto put_entries;
uncharge_payload:
	while (nr_charged) {
		nr_charged--;
		memcompress_entry_uncharge(entries[nr_charged],
					  payload[nr_charged].length);
	}
free_payload:
	for (i = 0; i < nr_pages; i++)
		if (payload[i].length)
			zpool_free(memcompress_pool, payload[i].handle);
put_entries:
	for (i = 0; i < nr_pages; i++)
		memcompress_entry_put(entries[i]);
put_ctx:
	memcompress_reclaim_ctx_put(ctx);
	return ret;
}

void memcompress_rollback_folio(struct folio *folio)
{
	unsigned long base = memcompress_folio_token(folio);
	unsigned int nr_pages = folio_nr_pages(folio), i;

	if (!base || !folio_test_locked(folio) ||
	    nr_pages > MEMCOMPRESS_MAX_FOLIO_PAGES)
		return;
	for (i = 0; i < nr_pages; i++) {
		struct memcompress_entry *entry = memcompress_get_entry(base + i);
		bool drop_owner = false;

		if (!entry)
			continue;
		mutex_lock(&entry->lock);
		if (entry->folio == folio && entry->folio_owner &&
		    entry->nr_pages == nr_pages && entry->page_idx == i) {
			entry->folio_owner = false;
			drop_owner = true;
		}
		mutex_unlock(&entry->lock);
		/* Pending PTEs retain the physical folio reference until restored. */
		if (drop_owner)
			memcompress_entry_put(entry);
		memcompress_entry_put(entry);
	}
	folio->private = 0;
}

void memcompress_invalidate_folio(struct folio *folio)
{
	memcompress_rollback_folio(folio);
}

struct memcompress_entry *memcompress_load_folio_pin(unsigned long token)
{
	return memcompress_get_entry(token);
}

void memcompress_load_folio_commit(struct memcompress_entry *entry)
{
	memcompress_entry_put(entry);
	memcompress_entry_put(entry);
}

void memcompress_load_folio_abort(struct memcompress_entry *entry)
{
	memcompress_entry_put(entry);
}

struct folio *memcompress_pending_folio(struct memcompress_entry *entry,
				      unsigned int *page_idx)
{
	struct folio *folio = NULL;

	mutex_lock(&entry->lock);
	if (entry->state == MC_PENDING && entry->folio) {
		folio = entry->folio;
		folio_get(folio);
		if (page_idx)
			*page_idx = entry->page_idx;
	}
	mutex_unlock(&entry->lock);
	return folio;
}

bool memcompress_pending_folio_valid(struct memcompress_entry *entry,
				    struct folio *folio,
				    unsigned int page_idx)
{
	bool valid;

	mutex_lock(&entry->lock);
	valid = entry->state == MC_PENDING && entry->folio == folio &&
		entry->page_idx == page_idx;
	mutex_unlock(&entry->lock);
	return valid;
}

int memcompress_do_load_entry(struct memcompress_entry *entry, void *dst)
{
	struct memcompress_decomp_ctx *ctx;
	unsigned int dst_len = PAGE_SIZE;
	const void *src;
	int ret;

	if (!entry || !dst)
		return -EINVAL;
	mutex_lock(&entry->lock);
	if (entry->refresh_pending || entry->state == MC_PENDING) {
		ret = -EAGAIN;
		goto unlock;
	}
	if (entry->state == MC_SAMEFILL) {
		memset64(dst, entry->handle, PAGE_SIZE / sizeof(u64));
		ret = 0;
		goto unlock;
	}
	if (!entry->length || entry->length > PAGE_SIZE) {
		ret = -EIO;
		goto unlock;
	}
	local_lock(&memcompress_decomp_ctxs.lock);
	ctx = this_cpu_ptr(&memcompress_decomp_ctxs);
	src = zpool_map_handle(memcompress_pool, entry->handle, ZPOOL_MM_RO);
	if (!src) {
		ret = -EIO;
	} else if (entry->length == PAGE_SIZE) {
		memcpy(dst, src, PAGE_SIZE);
		ret = 0;
	} else {
		ret = crypto_comp_decompress(ctx->tfm, src, entry->length, dst,
					     &dst_len);
		if (!ret && dst_len != PAGE_SIZE)
			ret = -EIO;
	}
	if (src)
		zpool_unmap_handle(memcompress_pool, entry->handle);
	local_unlock(&memcompress_decomp_ctxs.lock);
unlock:
	mutex_unlock(&entry->lock);
	return ret;
}

int memcompress_load_folio(struct memcompress_entry *entry, struct folio *folio)
{
	int ret;

	if (!folio || folio_test_large(folio))
		return -EINVAL;
	ret = memcompress_do_load_entry(entry, page_address(folio_page(folio, 0)));
	if (ret)
		return ret;
	arch_swap_restore(swp_entry(SWP_MEMCOMPRESS, entry->token), folio);
	flush_dcache_folio(folio);
	folio_mark_uptodate(folio);
	return 0;
}

int memcompress_read_token(unsigned long token, struct folio *folio)
{
	struct memcompress_entry *entry = memcompress_get_entry(token);
	int ret;

	if (!entry)
		return -ENOENT;
	ret = memcompress_load_folio(entry, folio);
	memcompress_entry_put(entry);
	return ret;
}

int memcompress_migrate_folio(struct folio *dst, struct folio *src)
{
	unsigned long base = memcompress_folio_token(src);
	unsigned int nr_pages = folio_nr_pages(src), i;

	if (!base)
		return 0;
	if (nr_pages > MEMCOMPRESS_MAX_FOLIO_PAGES ||
	    folio_nr_pages(dst) != nr_pages || !folio_test_locked(src) ||
	    !folio_test_locked(dst) || dst->private)
		return -EINVAL;
	for (i = 0; i < nr_pages; i++) {
		struct memcompress_entry *entry = memcompress_get_entry(base + i);
		bool matches;

		if (!entry)
			goto rollback;
		mutex_lock(&entry->lock);
		matches = entry->folio == src && entry->nr_pages == nr_pages &&
			entry->page_idx == i;
		if (matches) {
			folio_get(dst);
			entry->folio = dst;
		}
		mutex_unlock(&entry->lock);
		memcompress_entry_put(entry);
		if (!matches)
			goto rollback;
		folio_put(src);
	}
	dst->private = src->private;
	src->private = 0;
	return 0;
rollback:
	dst->private = src->private;
	memcompress_migrate_folio_rollback(dst, src);
	return -EAGAIN;
}

void memcompress_migrate_folio_rollback(struct folio *dst, struct folio *src)
{
	unsigned long base = memcompress_folio_token(dst);
	unsigned int nr_pages = folio_nr_pages(src), i;

	if (!base || nr_pages > MEMCOMPRESS_MAX_FOLIO_PAGES)
		return;
	for (i = 0; i < nr_pages; i++) {
		struct memcompress_entry *entry = memcompress_get_entry(base + i);
		bool moved = false;

		if (!entry)
			continue;
		mutex_lock(&entry->lock);
		if (entry->folio == dst) {
			folio_get(src);
			entry->folio = src;
			moved = true;
		}
		mutex_unlock(&entry->lock);
		memcompress_entry_put(entry);
		if (moved)
			folio_put(dst);
	}
	src->private = dst->private;
	dst->private = 0;
}

void memcompress_reclaim_queue(int nid, unsigned int nr_pages)
{
	if (nid >= 0 && nid < MAX_NUMNODES)
		atomic_long_add(nr_pages, &memcompress_nodes[nid].inflight);
}

void memcompress_reclaim_complete(int nid, unsigned int nr_pages, bool success)
{
	struct memcompress_reclaim_node *node;

	if (nid < 0 || nid >= MAX_NUMNODES)
		return;
	node = &memcompress_nodes[nid];
	if (success)
		atomic64_add(nr_pages, &node->success);
	atomic_long_sub(nr_pages, &node->inflight);
	wake_up_all(&node->wait);
}

bool memcompress_reclaim_inflight(int nid)
{
	return nid >= 0 && nid < MAX_NUMNODES &&
		atomic_long_read(&memcompress_nodes[nid].inflight) > 0;
}

u64 memcompress_reclaim_progress(int nid)
{
	return nid >= 0 && nid < MAX_NUMNODES ?
		atomic64_read(&memcompress_nodes[nid].success) : 0;
}

long memcompress_wait_reclaim_progress(int nid, u64 cursor, long timeout)
{
	long ret;

	if (nid < 0 || nid >= MAX_NUMNODES || timeout < 1)
		return 0;
	if (!memcompress_reclaim_inflight(nid) ||
	    memcompress_reclaim_progress(nid) != cursor)
		return timeout;
	ret = wait_event_interruptible_timeout(memcompress_nodes[nid].wait,
		memcompress_reclaim_progress(nid) != cursor ||
		!memcompress_reclaim_inflight(nid), timeout);
	return ret > 0 ? ret : 1;
}

static ssize_t enabled_show(struct kobject *kobj, struct kobj_attribute *attr,
			    char *buf)
{
	return sysfs_emit(buf, "%c\n", memcompress_available() ? 'Y' : 'N');
}

static ssize_t enabled_store(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	bool enabled;
	unsigned long flags;
	int ret = kstrtobool(buf, &enabled);

	if (ret)
		return ret;
	spin_lock_irqsave(&memcompress_context_lock, flags);
	WRITE_ONCE(memcompress_enabled_user_set, true);
	/* Publish the same initialized backend when enabled through sysfs. */
	smp_store_release(&memcompress_enabled, enabled);
	spin_unlock_irqrestore(&memcompress_context_lock, flags);
	wake_up_all(&memcompress_context_wait);
	return count;
}

static ssize_t compressor_show(struct kobject *kobj, struct kobj_attribute *attr,
			       char *buf)
{
	return sysfs_emit(buf, "%s\n", memcompress_compressor);
}

static ssize_t zpool_show(struct kobject *kobj, struct kobj_attribute *attr,
			  char *buf)
{
	return sysfs_emit(buf, "%s\n", memcompress_zpool_type);
}

static ssize_t stat_show(struct kobject *kobj, struct kobj_attribute *attr,
			 char *buf)
{
	return sysfs_emit(buf, "%ld %ld %llu\n",
		atomic_long_read(&memcompress_stored_bytes),
		atomic_long_read(&memcompress_compressed_bytes),
		zpool_get_total_size(memcompress_pool));
}

static ssize_t debug_stat_show(struct kobject *kobj, struct kobj_attribute *attr,
			       char *buf)
{
	return sysfs_emit(buf,
		"stored_bytes %ld\ncompressed_bytes %ld\npool_bytes %llu\n"
		"same_filled_pages %ld\nclassifier_calls %lld\n"
		"classifier_bypasses %lld\n",
		atomic_long_read(&memcompress_stored_bytes),
		atomic_long_read(&memcompress_compressed_bytes),
		zpool_get_total_size(memcompress_pool),
		atomic_long_read(&memcompress_same_filled_pages),
		atomic64_read(&memcompress_classifier_calls),
		atomic64_read(&memcompress_classifier_bypasses));
}

static struct kobj_attribute enabled_attr = __ATTR_RW(enabled);
static struct kobj_attribute compressor_attr = __ATTR_RO(compressor);
static struct kobj_attribute zpool_attr = __ATTR_RO(zpool);
static struct kobj_attribute stat_attr = __ATTR_RO(stat);
static struct kobj_attribute debug_stat_attr = __ATTR_RO(debug_stat);

static struct attribute *memcompress_attrs[] = {
	&enabled_attr.attr,
	&compressor_attr.attr,
	&zpool_attr.attr,
	&stat_attr.attr,
	&debug_stat_attr.attr,
	NULL,
};

static const struct attribute_group memcompress_attr_group = {
	.attrs = memcompress_attrs,
};

static void __init memcompress_choose_compressor(void)
{
	unsigned long highest = 0, second = 0;
	unsigned int clusters = 0;
	int cpu, other;

	if (memcompress_compressor_user_set)
		return;
	for_each_possible_cpu(cpu) {
		unsigned long capacity = 0;
		int cluster = topology_cluster_id(cpu);
		bool seen = false;

		for_each_possible_cpu(other) {
			if (other >= cpu)
				break;
			if (topology_cluster_id(other) == cluster) {
				seen = true;
				break;
			}
		}
		if (seen)
			continue;
		for_each_possible_cpu(other)
			if (topology_cluster_id(other) == cluster)
				capacity = max(capacity, arch_scale_cpu_capacity(other));
		clusters++;
		if (capacity >= highest) {
			second = highest;
			highest = capacity;
		} else if (capacity > second) {
			second = capacity;
		}
	}
	if ((clusters < 2 ? 0 : highest - second) <
	    memcompress_capacity_threshold)
		strscpy(memcompress_compressor, "lz4", sizeof(memcompress_compressor));
	else if (crypto_has_comp("zstdp", 0, 0))
		strscpy(memcompress_compressor, "zstdp", sizeof(memcompress_compressor));
	else
		strscpy(memcompress_compressor, "zstd", sizeof(memcompress_compressor));
}

static int __init memcompress_init(void)
{
	struct kobject *kobj;
	unsigned int i, reserved;
	int cpu, nid, ret;

	memcompress_choose_compressor();
	memcompress_entry_cache = KMEM_CACHE(memcompress_entry, 0);
	if (!memcompress_entry_cache)
		return -ENOMEM;
	memcompress_pool = zpool_create_pool(memcompress_zpool_type, "memcompress",
					    GFP_KERNEL);
	if (!memcompress_pool) {
		ret = -ENOMEM;
		goto destroy_cache;
	}
	/* The local decoder lock requires a non-sleeping allocator mapping. */
	if (zpool_can_sleep_mapped(memcompress_pool)) {
		ret = -EINVAL;
		goto destroy_pool;
	}
	memcompress_nr_contexts = min(num_possible_cpus() * 4U, MC_MAX_CONTEXTS);
	for (i = 0; i < memcompress_nr_contexts; i++) {
		struct memcompress_reclaim_ctx *ctx = &memcompress_contexts[i];

		ctx->tfm = crypto_alloc_comp(memcompress_compressor, 0, 0);
		if (IS_ERR(ctx->tfm)) {
			ret = PTR_ERR(ctx->tfm);
			ctx->tfm = NULL;
			goto free_contexts;
		}
		ctx->dst = kmalloc(PAGE_SIZE * 2, GFP_KERNEL);
		if (!ctx->dst) {
			ret = -ENOMEM;
			goto free_contexts;
		}
		ctx->shadow_seq = 0x1bbcdc80U + i * 0x9e3779b9U;
	}
	for_each_possible_cpu(cpu) {
		struct memcompress_decomp_ctx *ctx;

		ctx = per_cpu_ptr(&memcompress_decomp_ctxs, cpu);
		local_lock_init(&ctx->lock);
		ctx->tfm = crypto_alloc_comp(memcompress_compressor, 0, 0);
		if (IS_ERR(ctx->tfm)) {
			ret = PTR_ERR(ctx->tfm);
			ctx->tfm = NULL;
			goto free_decomp_contexts;
		}
	}
	for (nid = 0; nid < MAX_NUMNODES; nid++)
		init_waitqueue_head(&memcompress_nodes[nid].wait);
	memcompress_context_all = GENMASK(memcompress_nr_contexts - 1, 0);
	memcompress_context_free = memcompress_context_all;
	reserved = min(num_possible_cpus(), memcompress_nr_contexts / 2);
	memcompress_context_foreground = memcompress_context_all &
		~GENMASK(reserved - 1, 0);
	memcompress_borrow_limit = reserved > 1;
	kobj = kobject_create_and_add("memcompress", mm_kobj);
	if (!kobj) {
		ret = -ENOMEM;
		goto free_decomp_contexts;
	}
	ret = sysfs_create_group(kobj, &memcompress_attr_group);
	if (ret) {
		kobject_put(kobj);
		goto free_decomp_contexts;
	}
	if (memcompress_auto_enable)
		schedule_delayed_work(&memcompress_auto_enable_worker,
				      msecs_to_jiffies(15000));
	pr_info("prepared %u contexts, %s/%s, auto_enable=%d\n", memcompress_nr_contexts,
		memcompress_compressor, memcompress_zpool_type, memcompress_auto_enable);
	return 0;

free_decomp_contexts:
	for_each_possible_cpu(cpu) {
		struct memcompress_decomp_ctx *ctx;

		ctx = per_cpu_ptr(&memcompress_decomp_ctxs, cpu);
		if (ctx->tfm)
			crypto_free_comp(ctx->tfm);
		ctx->tfm = NULL;
	}
free_contexts:
	for (i = 0; i < memcompress_nr_contexts; i++) {
		if (memcompress_contexts[i].tfm)
			crypto_free_comp(memcompress_contexts[i].tfm);
		kfree(memcompress_contexts[i].dst);
		memcompress_contexts[i].tfm = NULL;
		memcompress_contexts[i].dst = NULL;
	}
	memcompress_nr_contexts = 0;
destroy_pool:
	zpool_destroy_pool(memcompress_pool);
destroy_cache:
	kmem_cache_destroy(memcompress_entry_cache);
	pr_warn("initialization failed: %d\n", ret);
	return ret;
}
late_initcall(memcompress_init);
