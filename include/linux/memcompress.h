/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MEMCOMPRESS_H
#define _LINUX_MEMCOMPRESS_H

#include <linux/mm_types.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/xarray.h>

#define MEMCOMPRESS_MAX_FOLIO_PAGES 16U

struct memcompress_entry;
struct memcompress_reclaim_ctx;

enum memcompress_reclaim_source {
	MEMCOMPRESS_RECLAIM_DIRECT,
	MEMCOMPRESS_RECLAIM_KSWAPD,
	MEMCOMPRESS_RECLAIM_WORKER,
	MEMCOMPRESS_RECLAIM_BURST,
	MEMCOMPRESS_RECLAIM_SOURCE_NR,
};

/* The swap type is reserved in swap.h, independently of architecture PTEs. */
static inline bool is_memcompress_entry(swp_entry_t entry)
{
#ifdef CONFIG_MEMCOMPRESS
	return swp_type(entry) == SWP_MEMCOMPRESS;
#else
	return false;
#endif
}

static inline unsigned long memcompress_folio_token(struct folio *folio)
{
	swp_entry_t entry = { .val = (unsigned long)READ_ONCE(folio->private) };

	return is_memcompress_entry(entry) ? swp_offset(entry) : 0;
}

#ifdef CONFIG_MEMCOMPRESS
bool memcompress_available(void);
bool is_memcompress_shadow(void *shadow);
unsigned long memcompress_shadow_token(void *shadow);
bool memcompress_reserve_eligible(struct folio *folio);
bool memcompress_fresh_reservation(struct folio *folio);
/* Pin the folio's anon_vma before reserve until store/rollback completes. */
bool memcompress_reserve(struct folio *folio, bool *stored);
bool memcompress_store_cache(struct folio *folio, unsigned long *token);
bool memcompress_store_after_unmap(struct folio *folio,
				  struct memcompress_reclaim_ctx **ctxp);
void memcompress_rollback_folio(struct folio *folio);
/* Requires the locked reservation folio and the caller's anon_vma pin. */
void memcompress_restore_ptes(struct folio *folio);
void memcompress_invalidate_folio(struct folio *folio);

bool memcompress_reclaim_ctx_precheck(unsigned int nr_pages,
				     enum memcompress_reclaim_source source);
struct memcompress_reclaim_ctx *
memcompress_reclaim_ctx_get(unsigned int nr_pages,
			   enum memcompress_reclaim_source source);
void memcompress_reclaim_ctx_put(struct memcompress_reclaim_ctx *ctx);

/* A PTE owns one reference. Lookup pins are additional temporary references. */
struct memcompress_entry *memcompress_get_entry(unsigned long token);
struct memcompress_entry *memcompress_load_folio_pin(unsigned long token);
bool memcompress_entry_get(unsigned long token);
bool memcompress_entry_present(unsigned long token);
void memcompress_entry_put(struct memcompress_entry *entry);
void memcompress_invalidate(unsigned long token);
void memcompress_invalidate_nr(unsigned long token, unsigned int nr_pages);
unsigned int memcompress_entry_nr_pages(unsigned long token,
				       unsigned long *base_token);
bool memcompress_entry_stat(unsigned long token, unsigned long *compressed,
			   int *mapcount);
bool memcompress_entry_set_refresh_pending(unsigned long token);
void memcompress_entry_clear_refresh_pending(unsigned long token);
unsigned int memcompress_pte_batch(pte_t *ptep, unsigned int max_nr);

int memcompress_do_load_entry(struct memcompress_entry *entry, void *dst);
int memcompress_load_folio(struct memcompress_entry *entry, struct folio *folio);
int memcompress_read_token(unsigned long token, struct folio *folio);
struct folio *memcompress_pending_folio(struct memcompress_entry *entry,
				      unsigned int *page_idx);
bool memcompress_pending_folio_valid(struct memcompress_entry *entry,
				    struct folio *folio,
				    unsigned int page_idx);
void memcompress_load_folio_commit(struct memcompress_entry *entry);
void memcompress_load_folio_abort(struct memcompress_entry *entry);
int memcompress_migrate_folio(struct folio *dst, struct folio *src);
void memcompress_migrate_folio_rollback(struct folio *dst, struct folio *src);
void memcompress_reclaim_queue(int nid, unsigned int nr_pages);
void memcompress_reclaim_complete(int nid, unsigned int nr_pages, bool success);
bool memcompress_reclaim_inflight(int nid);
u64 memcompress_reclaim_progress(int nid);
long memcompress_wait_reclaim_progress(int nid, u64 cursor, long timeout);
#else
static inline bool memcompress_available(void) { return false; }
static inline bool is_memcompress_shadow(void *shadow) { return false; }
static inline unsigned long memcompress_shadow_token(void *shadow) { return 0; }
static inline bool memcompress_reserve_eligible(struct folio *folio)
{
	return false;
}
static inline bool memcompress_reserve(struct folio *folio, bool *stored)
{
	if (stored)
		*stored = false;
	return false;
}
static inline bool memcompress_store_cache(struct folio *folio,
					 unsigned long *token)
{
	return false;
}
static inline bool memcompress_store_after_unmap(struct folio *folio,
					struct memcompress_reclaim_ctx **ctxp)
{
	return false;
}
static inline void memcompress_rollback_folio(struct folio *folio) { }
static inline void memcompress_restore_ptes(struct folio *folio) { }
static inline void memcompress_invalidate_folio(struct folio *folio) { }
static inline bool memcompress_reclaim_ctx_precheck(unsigned int nr_pages,
				 enum memcompress_reclaim_source source)
{
	return false;
}
static inline struct memcompress_reclaim_ctx *
memcompress_reclaim_ctx_get(unsigned int nr_pages,
			   enum memcompress_reclaim_source source)
{
	return NULL;
}
static inline void
memcompress_reclaim_ctx_put(struct memcompress_reclaim_ctx *ctx) { }
static inline bool memcompress_entry_get(unsigned long token) { return false; }
static inline bool memcompress_entry_present(unsigned long token)
{
	return false;
}
static inline void memcompress_invalidate(unsigned long token) { }
static inline void memcompress_invalidate_nr(unsigned long token,
					    unsigned int nr_pages) { }
static inline struct memcompress_entry *
memcompress_get_entry(unsigned long token)
{
	return NULL;
}
static inline struct memcompress_entry *
memcompress_load_folio_pin(unsigned long token)
{
	return NULL;
}
static inline void memcompress_entry_put(struct memcompress_entry *entry) { }
static inline void
memcompress_load_folio_commit(struct memcompress_entry *entry) { }
static inline void
memcompress_load_folio_abort(struct memcompress_entry *entry) { }
static inline unsigned int
memcompress_entry_nr_pages(unsigned long token, unsigned long *base_token)
{
	if (base_token)
		*base_token = token;
	return 1;
}
static inline bool memcompress_entry_stat(unsigned long token,
					 unsigned long *compressed, int *mapcount)
{
	if (compressed)
		*compressed = 0;
	if (mapcount)
		*mapcount = 0;
	return false;
}
static inline bool
memcompress_entry_set_refresh_pending(unsigned long token)
{
	return false;
}
static inline void
memcompress_entry_clear_refresh_pending(unsigned long token) { }
static inline unsigned int memcompress_pte_batch(pte_t *ptep, unsigned int max_nr)
{
	return 0;
}
static inline struct folio *
memcompress_pending_folio(struct memcompress_entry *entry, unsigned int *page_idx)
{
	return NULL;
}
static inline bool
memcompress_pending_folio_valid(struct memcompress_entry *entry,
			       struct folio *folio, unsigned int page_idx)
{
	return false;
}
static inline int memcompress_load_folio(struct memcompress_entry *entry,
				       struct folio *folio)
{
	return -ENOENT;
}
static inline int memcompress_do_load_entry(struct memcompress_entry *entry,
					   void *dst)
{
	return -ENOENT;
}
static inline int memcompress_read_token(unsigned long token, struct folio *folio)
{
	return -ENOENT;
}
static inline int memcompress_migrate_folio(struct folio *dst, struct folio *src)
{
	return 0;
}
static inline void memcompress_migrate_folio_rollback(struct folio *dst,
						    struct folio *src) { }
static inline bool memcompress_fresh_reservation(struct folio *folio)
{
	return false;
}
static inline void memcompress_reclaim_queue(int nid, unsigned int nr_pages) { }
static inline void memcompress_reclaim_complete(int nid, unsigned int nr_pages,
					       bool success) { }
static inline bool memcompress_reclaim_inflight(int nid) { return false; }
static inline u64 memcompress_reclaim_progress(int nid) { return 0; }
static inline long memcompress_wait_reclaim_progress(int nid, u64 cursor,
						    long timeout)
{
	return 0;
}
#endif

#endif /* _LINUX_MEMCOMPRESS_H */
