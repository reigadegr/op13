// SPDX-License-Identifier: GPL-2.0-only
/*
 * Bounded memcompress data-integrity and cross-implementation observations.
 *
 * Only this process's anonymous mapping is reclaimed, using MADV_PAGEOUT.
 * No global tunable is changed. Test data uses 2 MiB (8 MiB with THP tests),
 * doubled after fork COW. Run on a memcompress kernel with no configured swap devices;
 * otherwise pagemap cannot identify this private swap type portably.
 * Strict rollback and smaps checks are opt-in port regression assertions.
 * Token PTEs can refer to PENDING pages; they do not prove codec completion.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <linux/userfaultfd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/swap.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../kselftest.h"

#define THP_ALIGN (64UL * 1024)
static size_t data_size = 2UL * 1024 * 1024;
static unsigned int thp_pages;
static bool thp_fail_alloc;
#define PM_PRESENT (1ULL << 63)
#define PM_SWAP (1ULL << 62)
#define PM_FRAME_MASK ((1ULL << 55) - 1)
#define PM_TYPE_MASK 31ULL
#define TEST_COUNT 5

enum pattern {
	SAMEFILL,
	COMPRESSIBLE,
	RANDOM,
};

static size_t page_size, nr_pages;
static uint64_t *data;
static uint64_t *before, *after;
static int pagemap_fd;
static bool token_seen;
static bool strict_rollback, strict_smaps;
/* Confirmed for the vendor image and the current op13 configuration only. */
static unsigned int token_type = 27;

static void timeout_handler(int sig)
{
	static const char msg[] = "memcompress selftest timed out\n";
	ssize_t ret;

	(void)sig;
	ret = write(STDERR_FILENO, msg, sizeof(msg) - 1);
	(void)ret;
	_exit(KSFT_FAIL);
}

static bool swap_devices_present(void)
{
	FILE *file = fopen("/proc/swaps", "r");
	char line[512];
	bool present = true;

	if (!file)
		return true;
	if (fgets(line, sizeof(line), file))
		present = fgets(line, sizeof(line), file) != NULL;
	fclose(file);
	return present;
}

/* Missing enabled is an unknown state, as on the vendor sysfs ABI. */
static int admission_status(void)
{
	FILE *file = fopen("/sys/kernel/mm/memcompress/enabled", "r");
	int value, ret;

	if (!file)
		return errno == ENOENT ? 0 : -errno;
	value = fgetc(file);
	ret = ferror(file) ? -EIO : -EINVAL;
	fclose(file);
	if (value == 'Y' || value == '1')
		return 1;
	if (value == 'N' || value == '0')
		return -EOPNOTSUPP;
	return ret;
}

static uint64_t next_random(uint64_t *state)
{
	*state ^= *state >> 12;
	*state ^= *state << 25;
	*state ^= *state >> 27;
	return *state * UINT64_C(2685821657736338717);
}

static uint64_t pattern_word(enum pattern pattern, unsigned int salt,
			     size_t page, size_t word, uint64_t *state)
{
	uint64_t value = UINT64_C(0x6d656d636f6d7000) ^
			 ((uint64_t)salt << 32) ^ page;

	if (pattern == RANDOM)
		return next_random(state);
	if (pattern == COMPRESSIBLE)
		value ^= (word & 7) * UINT64_C(0x0102030405060708);
	return value;
}

static bool visit_data(enum pattern pattern, unsigned int salt, bool fill)
{
	size_t page, word;

	for (page = 0; page < nr_pages; page++) {
		uint64_t state = UINT64_C(0x243f6a8885a308d3) ^
				 ((uint64_t)salt << 32) ^ page;

		for (word = 0; word < page_size / sizeof(*data); word++) {
			uint64_t expected = pattern_word(pattern, salt, page,
							 word, &state);
			size_t index = page * page_size / sizeof(*data) + word;

			if (fill)
				data[index] = expected;
			else if (data[index] != expected)
				return false;
		}
	}
	return true;
}

/* Read all entries at once without touching any test data. */
static int snapshot(uint64_t *entries, size_t *swapped, size_t *resident)
{
	off_t offset = (uintptr_t)data / page_size * sizeof(*entries);
	size_t bytes = nr_pages * sizeof(*entries), done = 0, page;

	while (done < bytes) {
		ssize_t ret = pread(pagemap_fd, (char *)entries + done,
				    bytes - done, offset + done);

		if (ret < 0 && errno == EINTR)
			continue;
		if (ret <= 0)
			return -EIO;
		done += ret;
	}
	*swapped = 0;
	*resident = 0;
	for (page = 0; page < nr_pages; page++) {
		uint64_t entry = entries[page];

		if (entry & PM_PRESENT) {
			(*resident)++;
			continue;
		}
		if (!(entry & PM_SWAP))
			return -EAGAIN;
		/* Swap type and token are redacted without CAP_SYS_ADMIN. */
		if (!(entry & PM_FRAME_MASK))
			return -EACCES;
		/* Migration and other special entries do not establish our token. */
		if ((entry & PM_TYPE_MASK) != token_type)
			return -EAGAIN;
		if (!(entry & (PM_FRAME_MASK & ~PM_TYPE_MASK)))
			return -EIO;
		(*swapped)++;
	}
	return 0;
}

static int mapping_swap_kb(unsigned long long *swap_kb)
{
	FILE *file = fopen("/proc/self/smaps", "r");
	unsigned long start, end;
	char line[512];
	bool selected = false;
	int ret = -ENOENT;

	if (!file)
		return -errno;
	while (fgets(line, sizeof(line), file)) {
		if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
			selected = start == (uintptr_t)data &&
				   end == (uintptr_t)data + data_size;
		} else if (selected && sscanf(line, "Swap: %llu kB", swap_kb) == 1) {
			ret = 0;
			break;
		}
	}
	fclose(file);
	return ret;
}

/* A pass requires stable, visible token PTEs on this mapping with no disk swap. */
static int pageout_and_observe(size_t *swapped)
{
	size_t resident, second_swapped;
	unsigned int attempt;
	int ret;

	for (attempt = 0; attempt < 3; attempt++) {
		ret = admission_status();
		if (ret < 0)
			return ret;
		if (madvise(data, data_size, MADV_PAGEOUT))
			return -errno;
		ret = snapshot(before, swapped, &resident);
		if (ret)
			return ret;
		if (!*swapped)
			continue;
		usleep(10000);
		ret = snapshot(after, &second_swapped, &resident);
		if (ret)
			return ret;
		if (*swapped == second_swapped &&
		    !memcmp(before, after, nr_pages * sizeof(*before))) {
			token_seen = true;
			return 0;
		}
	}
	return -EAGAIN;
}

static void observation_failed(int ret, const char *name)
{
	switch (-ret) {
	case EAGAIN:
	case EOPNOTSUPP:
	case EACCES:
	case EPERM:
		ksft_test_result_skip("%s: required observation unavailable (%s)\n",
				      name, strerror(-ret));
		break;
	default:
		ksft_test_result_fail("%s: observation failed (%s)\n",
				      name, strerror(-ret));
	}
}

/* Even an inconclusive pageout must not hide a data-integrity failure. */
static void observation_or_data_failed(int ret, enum pattern pattern,
				       unsigned int salt, const char *name)
{
	if (!visit_data(pattern, salt, false))
		ksft_test_result_fail("%s: restored data mismatch\n", name);
	else
		observation_failed(ret, name);
}

static void test_roundtrip(enum pattern pattern, const char *name)
{
	size_t swapped;
	int ret;

	visit_data(pattern, 0, true);
	ret = pageout_and_observe(&swapped);
	if (ret) {
		observation_or_data_failed(ret, pattern, 0, name);
		return;
	}
	ksft_test_result(visit_data(pattern, 0, false),
			 "%s: %zu memcompress token PTEs\n", name, swapped);
}

static int send_byte(int fd)
{
	ssize_t ret;

	do {
		ret = write(fd, "x", 1);
	} while (ret < 0 && errno == EINTR);
	return ret == 1 ? 0 : -1;
}

static int receive_byte(int fd)
{
	char value;
	ssize_t ret;

	do {
		ret = read(fd, &value, 1);
	} while (ret < 0 && errno == EINTR);
	return ret == 1 ? 0 : -1;
}

static void test_fork_cow(void)
{
	const char *name = "fork memcompress token PTEs and isolate parent/child writes";
	int child_ready[2], parent_ready[2], status, ret;
	size_t swapped;
	bool valid;
	pid_t child;

	visit_data(COMPRESSIBLE, 0, true);
	ret = pageout_and_observe(&swapped);
	if (ret) {
		observation_or_data_failed(ret, COMPRESSIBLE, 0, name);
		return;
	}
	if (pipe(child_ready)) {
		ksft_test_result_fail("%s: pipe failed\n", name);
		return;
	}
	if (pipe(parent_ready)) {
		close(child_ready[0]);
		close(child_ready[1]);
		ksft_test_result_fail("%s: pipe failed\n", name);
		return;
	}
	child = fork();
	if (!child) {
		alarm(15);
		close(child_ready[0]);
		close(parent_ready[1]);
		valid = visit_data(COMPRESSIBLE, 0, false);
		visit_data(COMPRESSIBLE, 1, true);
		valid &= !send_byte(child_ready[1]);
		valid &= !receive_byte(parent_ready[0]);
		valid &= visit_data(COMPRESSIBLE, 1, false);
		_exit(valid ? KSFT_PASS : KSFT_FAIL);
	}
	close(child_ready[1]);
	close(parent_ready[0]);
	if (child < 0) {
		ksft_test_result_fail("%s: fork failed\n", name);
	} else {
		valid = !receive_byte(child_ready[0]);
		valid &= visit_data(COMPRESSIBLE, 0, false);
		visit_data(COMPRESSIBLE, 2, true);
		valid &= !send_byte(parent_ready[1]);
		do {
			ret = waitpid(child, &status, 0);
		} while (ret < 0 && errno == EINTR);
		valid &= ret == child && WIFEXITED(status) &&
			 WEXITSTATUS(status) == KSFT_PASS;
		valid &= visit_data(COMPRESSIBLE, 2, false);
		ksft_test_result(valid, "%s: %zu memcompress token PTEs\n", name, swapped);
	}
	close(child_ready[0]);
	close(parent_ready[1]);
}

static void test_smaps(void)
{
	const char *name = "smaps Swap observation across memcompress token faults";
	unsigned long long swap_kb = 0, restored_swap_kb = 0;
	size_t swapped, resident, second_swapped;
	size_t restored_swapped, restored_resident;
	bool stable, valid;
	int ret, smaps_ret;

	visit_data(COMPRESSIBLE, 3, true);
	ret = pageout_and_observe(&swapped);
	if (ret) {
		observation_or_data_failed(ret, COMPRESSIBLE, 3, name);
		return;
	}
	smaps_ret = mapping_swap_kb(&swap_kb);
	ret = snapshot(after, &second_swapped, &resident);
	if (ret) {
		observation_or_data_failed(ret, COMPRESSIBLE, 3, name);
		return;
	}
	stable = swapped == second_swapped &&
		 !memcmp(before, after, nr_pages * sizeof(*before));
	valid = swap_kb == swapped * (page_size / 1024);
	if (!visit_data(COMPRESSIBLE, 3, false)) {
		ksft_test_result_fail("%s: restored data mismatch\n", name);
		return;
	}
	if (smaps_ret) {
		observation_failed(smaps_ret, name);
		return;
	}
	ksft_print_msg("before faults: token PTEs=%zu Swap=%llu kB stable=%d\n",
		       swapped, swap_kb, stable);
	/* A later observation failure must not hide a known count mismatch. */
	if (strict_smaps && stable && !valid) {
		ksft_test_result_fail("%s: pre-fault Swap count mismatch\n", name);
		return;
	}
	ret = snapshot(after, &second_swapped, &resident);
	if (ret) {
		observation_failed(ret, name);
		return;
	}
	ret = mapping_swap_kb(&restored_swap_kb);
	if (ret) {
		observation_failed(ret, name);
		return;
	}
	ksft_print_msg("after faults: token PTEs=%zu resident=%zu Swap=%llu kB\n",
		       second_swapped, resident, restored_swap_kb);
	ret = snapshot(before, &restored_swapped, &restored_resident);
	if (ret) {
		observation_failed(ret, name);
		return;
	}
	if (strict_smaps && (!stable || second_swapped ||
	    memcmp(before, after, nr_pages * sizeof(*before)))) {
		ksft_test_result_skip("%s: mapping changed around smaps observation\n", name);
		return;
	}
	valid &= resident == nr_pages && !restored_swap_kb;
	ksft_test_result(!strict_smaps || valid, "%s: strict=%d\n",
			 name, strict_smaps);
}

static void test_rejected_pages(void)
{
	const char *name = "repeated incompressible pageout preserves data";
	size_t swapped, resident;
	unsigned int round;
	bool valid = true;
	int ret;

	if (!token_seen) {
		ksft_test_result_skip("%s: no observed token control\n", name);
		return;
	}
	for (round = 0; round < 3; round++) {
		ret = admission_status();
		if (ret < 0) {
			observation_failed(ret, name);
			return;
		}
		visit_data(RANDOM, round, true);
		if (madvise(data, data_size, MADV_PAGEOUT)) {
			observation_or_data_failed(-errno, RANDOM, round, name);
			return;
		}
		ret = snapshot(before, &swapped, &resident);
		if (ret) {
			observation_or_data_failed(ret, RANDOM, round, name);
			return;
		}
		/* Check before reading: a read would hide a leaked PENDING PTE. */
		ksft_print_msg("incompressible round %u: token PTEs=%zu resident=%zu\n",
			       round + 1, swapped, resident);
		if (strict_rollback)
			valid &= !swapped && resident == nr_pages;
		valid &= visit_data(RANDOM, round, false);
		if (!valid) {
			ksft_test_result_fail("%s: rollback or data mismatch in round %u\n",
					      name, round + 1);
			return;
		}
	}
	ksft_test_result(valid, "%s: three rounds, strict=%d\n",
			 name, strict_rollback);
}


/* PFN contiguity alone is insufficient: require compound head/tail flags. */
static bool compound_group(size_t start)
{
	uint64_t entries[16], flags, pfn;
	int fd = open("/proc/kpageflags", O_RDONLY);
	unsigned int i;
	bool valid = fd >= 0;

	if (!valid || pread(pagemap_fd, entries, thp_pages * sizeof(*entries),
		((uintptr_t)data / page_size + start) * sizeof(*entries)) !=
		(ssize_t)(thp_pages * sizeof(*entries))) {
		if (fd >= 0)
			close(fd);
		return false;
	}
	pfn = entries[0] & PM_FRAME_MASK;
	for (i = 0; i < thp_pages && valid; i++) {
		valid = (entries[i] & PM_PRESENT) && pfn &&
			(entries[i] & PM_FRAME_MASK) == pfn + i &&
			pread(fd, &flags, sizeof(flags), (pfn + i) * sizeof(flags)) ==
			(ssize_t)sizeof(flags);
		if (valid)
			valid = !!(flags & (1ULL << (i ? 16 : 15)));
	}
	/* The next physical page must not be another tail of this folio. */
	if (valid)
		valid = pread(fd, &flags, sizeof(flags),
			(pfn + thp_pages) * sizeof(flags)) == (ssize_t)sizeof(flags) &&
			!(flags & (1ULL << 16));
	close(fd);
	return valid;
}

static bool prepare_thp(void)
{
	return !madvise(data, data_size, MADV_DONTNEED) &&
		!madvise(data, data_size, MADV_HUGEPAGE) &&
		visit_data(COMPRESSIBLE, 0, true) && compound_group(0);
}

/* Admission can leave a stable partial batch; wait for the whole fixture. */
static bool thp_pageout(void)
{
	size_t swapped = 0;
	unsigned int attempt;
	int ret = 0;

	for (attempt = 0; attempt < 20; attempt++) {
		ret = pageout_and_observe(&swapped);
		if (!ret && swapped == nr_pages)
			return true;
		if (ret && ret != -EAGAIN)
			break;
		usleep(10000);
	}
	ksft_print_msg("THP fixture incomplete: ret=%d tokens=%zu expected=%zu\n",
		       ret, swapped, nr_pages);
	return false;
}

static uint64_t monotonic_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static void test_thp_access(bool random, bool nohuge)
{
	const char *name = nohuge ? "THP disabled before recovery" :
		random ? "THP random grouped recovery" : "THP sequential grouped recovery";
	size_t *order = calloc(nr_pages, sizeof(*order));
	size_t swapped, resident, touches, i, j, word;
	uint64_t state = 0x6d656d636f6d7072ULL, start, entry;
	cpu_set_t saved, pinned;
	int cpu = sched_getcpu();
	bool affinity = !sched_getaffinity(0, sizeof(saved), &saved);
	bool valid;
	unsigned int round;

	/* MADV_PAGEOUT drains only the calling CPU's pending LRU additions. */
	CPU_ZERO(&pinned);
	if (cpu >= 0)
		CPU_SET(cpu, &pinned);
	valid = affinity && cpu >= 0 && !sched_setaffinity(0, sizeof(pinned), &pinned);
	valid &= order && prepare_thp();
	if (valid && nohuge)
		valid = !madvise(data, data_size, MADV_NOHUGEPAGE);
	for (i = 0; order && i < nr_pages; i++)
		order[i] = i;
	if (random && order) {
		for (i = nr_pages - 1; i; i--) {
			size_t tmp;

			j = next_random(&state) % (i + 1);
			tmp = order[i];
			order[i] = order[j];
			order[j] = tmp;
		}
	}
	for (round = 0; valid && round < 3; round++) {
		valid = thp_pageout();
		touches = 0;
		start = monotonic_ns();
		for (i = 0; valid && i < nr_pages; i++) {
			j = order[i];
			valid = pread(pagemap_fd, &entry, sizeof(entry),
				((uintptr_t)data / page_size + j) * sizeof(entry)) ==
				(ssize_t)sizeof(entry);
			if (!valid)
				break;
			if (entry & PM_SWAP)
				touches++;
			for (word = 0; word < page_size / sizeof(*data); word++) {
				uint64_t expected = pattern_word(COMPRESSIBLE, 0, j, word, &state);

				valid &= data[j * page_size / sizeof(*data) + word] == expected;
			}
		}
		ksft_print_msg("%s round=%u pages=%zu first_touches=%zu access_ns=%llu\n",
			name, round + 1, nr_pages, touches,
			(unsigned long long)(monotonic_ns() - start));
		valid &= touches == nr_pages / (nohuge ? 1 : thp_pages);
		valid &= !snapshot(after, &swapped, &resident) && !swapped && resident == nr_pages;
		if (!nohuge)
			valid &= compound_group(0);
	}
	free(order);
	if (affinity)
		valid &= !sched_setaffinity(0, sizeof(saved), &saved);
	ksft_test_result(valid, "%s: %u-page folios, three full-data rounds\n", name, thp_pages);
}

/* Break a sibling PTE or VMA boundary before faulting the original group. */
static void test_thp_partial(bool split)
{
	size_t swapped, resident;
	bool valid = prepare_thp() && thp_pageout();

	if (valid) {
		if (split)
			valid = !mprotect((char *)data + page_size, page_size, PROT_READ);
		else
			valid = !madvise((char *)data + page_size, page_size, MADV_DONTNEED);
		valid &= __atomic_load_n(data, __ATOMIC_RELAXED) == UINT64_C(0x6d656d636f6d7000);
		/* Only the faulting token can have become resident. */
		if (split) {
			valid &= !snapshot(after, &swapped, &resident) &&
				swapped == nr_pages - 1 && resident == 1;
			valid &= !mprotect((char *)data + page_size, page_size,
					   PROT_READ | PROT_WRITE);
		} else {
			uint64_t state = 0;
			size_t word;

			for (word = 0; word < page_size / sizeof(*data); word++) {
				valid &= data[page_size / sizeof(*data) + word] == 0;
				data[page_size / sizeof(*data) + word] =
					pattern_word(COMPRESSIBLE, 0, 1, word, &state);
			}
			valid &= !snapshot(after, &swapped, &resident) &&
				swapped == nr_pages - 2 && resident == 2;
		}
		valid &= visit_data(COMPRESSIBLE, 0, false);
	}
	ksft_test_result(valid, "THP %s falls back without overwriting siblings\n",
			split ? "VMA split" : "discarded sibling");
}

static pthread_barrier_t fault_barrier;
static bool race_unmap;

static void *thp_fault_thread(void *arg)
{
	uintptr_t index = (uintptr_t)arg;
	size_t group;
	uint64_t state = 0;
	bool valid = true;

	pthread_barrier_wait(&fault_barrier);
	for (group = 0; group < nr_pages; group += thp_pages) {
		size_t page = group + index % thp_pages;
		uint64_t *ptr = data + page * page_size / sizeof(*data);

		if (race_unmap && index == 1) {
			void *addr = (void *)ptr;

			/* Other threads access page 0 only; never touch an unmapped VA. */
			valid &= !munmap(addr, page_size);
			valid &= mmap(addr, page_size, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == addr;
			if (valid)
				*ptr = 0x12345678;
		} else {
			size_t word;

			for (word = 0; word < page_size / sizeof(*data); word++)
				valid &= ptr[word] == pattern_word(COMPRESSIBLE, 0,
								 page, word, &state);
		}
	}
	return (void *)(uintptr_t)!valid;
}

static void test_thp_race(bool unmap)
{
	pthread_t threads[4];
	size_t page, word;
	unsigned int round, i, count = unmap ? 2 : 4;
	bool valid = true;
	void *result;

	race_unmap = unmap;
	for (round = 0; valid && round < 4; round++) {
		valid = prepare_thp() && thp_pageout();
		if (!valid)
			break;
		pthread_barrier_init(&fault_barrier, NULL, count);
		for (i = 0; i < count; i++)
			if (pthread_create(&threads[i], NULL, thp_fault_thread,
					   (void *)(uintptr_t)i))
				ksft_exit_fail_msg("cannot create fault thread\n");
		for (i = 0; i < count; i++) {
			pthread_join(threads[i], &result);
			valid &= !result;
		}
		pthread_barrier_destroy(&fault_barrier);
		if (unmap) {
			uint64_t state = 0, expected;

			for (page = 0; page < nr_pages; page++) {
				for (word = 0; word < page_size / sizeof(*data); word++) {
					if (page % thp_pages == 1)
						expected = word ? 0 : 0x12345678;
					else
						expected = pattern_word(COMPRESSIBLE, 0,
								page, word, &state);
					valid &= data[page * page_size / sizeof(*data) + word] ==
						 expected;
				}
			}
			/* Restore one VMA for the next controlled THP allocation. */
			valid &= mmap(data, data_size, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == (void *)data;
		} else {
			valid &= visit_data(COMPRESSIBLE, 0, false);
		}
	}
	ksft_test_result(valid, "THP concurrent %s preserves data (four rounds)\n",
			unmap ? "fault/unmap/remap" : "sibling faults");
}

static void test_thp_uffd(void)
{
	struct uffdio_api api = { .api = UFFD_API };
	struct uffdio_register reg = {
		.range = { .start = (uintptr_t)data, .len = data_size },
		.mode = UFFDIO_REGISTER_MODE_MISSING,
	};
	size_t swapped, resident;
	bool valid = prepare_thp() && thp_pageout();
	int fd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);

	valid &= fd >= 0;
	if (valid) {
		valid = !ioctl(fd, UFFDIO_API, &api) && !ioctl(fd, UFFDIO_REGISTER, &reg);
		valid &= __atomic_load_n(data, __ATOMIC_RELAXED) == UINT64_C(0x6d656d636f6d7000);
		valid &= !snapshot(after, &swapped, &resident) &&
			 resident == 1 && swapped == nr_pages - 1;
		valid &= visit_data(COMPRESSIBLE, 0, false);
	}
	if (fd >= 0)
		close(fd);
	ksft_test_result(valid, "THP UFFD missing registration keeps per-page faults\n");
}

static bool self_setting(const char *path, const char *value)
{
	int fd = open(path, O_WRONLY);
	bool valid;

	if (fd < 0)
		return false;
	valid = write(fd, value, strlen(value)) == (ssize_t)strlen(value);
	close(fd);
	return valid;
}

static void test_thp_write(void)
{
	size_t swapped, resident, index = thp_pages / 2;
	bool valid = prepare_thp() && thp_pageout();

	/* First access is a write to a nonzero subpage of the compressed group. */
	__atomic_store_n(data + index * page_size / sizeof(*data),
			 UINT64_C(0x6d656d636f6d7000) ^ index ^ 1, __ATOMIC_RELAXED);
	valid &= !snapshot(after, &swapped, &resident) && resident == thp_pages &&
		 swapped == nr_pages - thp_pages;
	valid &= data[index * page_size / sizeof(*data)] ==
		 (UINT64_C(0x6d656d636f6d7000) ^ index ^ 1);
	data[index * page_size / sizeof(*data)] ^= 1;
	valid &= visit_data(COMPRESSIBLE, 0, false);
	ksft_test_result(valid, "THP initial write fault targets the correct subpage\n");
}

static void test_thp_alloc_failure(void)
{
	size_t swapped, resident;
	bool valid = prepare_thp() && thp_pageout();
	FILE *file;
	int remaining = -1;

	/* The harness arms fail_page_alloc only for marked tasks and order > 0. */
	valid &= self_setting("/proc/self/make-it-fail", "1");
	valid &= __atomic_load_n(data, __ATOMIC_RELAXED) == UINT64_C(0x6d656d636f6d7000);
	valid &= !snapshot(after, &swapped, &resident) &&
		 resident == 1 && swapped == nr_pages - 1;
	file = fopen("/sys/kernel/debug/fail_page_alloc/times", "r");
	if (file) {
		valid &= fscanf(file, "%d", &remaining) == 1 && remaining == 0;
		fclose(file);
	} else {
		valid = false;
	}
	ksft_print_msg("THP fail_page_alloc: remaining=%d resident=%zu tokens=%zu\n",
		       remaining, resident, swapped);
	valid &= visit_data(COMPRESSIBLE, 0, false);
	valid &= self_setting("/proc/self/make-it-fail", "0");
	valid &= !snapshot(after, &swapped, &resident) && !swapped && resident == nr_pages;
	ksft_test_result(valid, "THP allocation failure falls back to base pages\n");
}

#define WRITEBACK_PATH "/sys/kernel/mm/memcompress/writeback"
#define WRITEBACK_STAT "/sys/kernel/mm/memcompress/writeback_stat"

static long named_stat(const char *path, const char *name)
{
	char key[64];
	long value, result = -1;
	FILE *file = fopen(path, "r");

	if (!file)
		return -1;
	while (fscanf(file, "%63s %ld", key, &value) == 2)
		if (!strcmp(key, name)) {
			result = value;
			break;
		}
	fclose(file);
	return result;
}

static long packed_stat(const char *name)
{
	return named_stat(WRITEBACK_STAT, name);
}

static int packed_control(const char *name, unsigned int count)
{
	char value[32], path[128];
	int fd, len, ret;

	snprintf(path, sizeof(path), "/sys/kernel/mm/memcompress/%s", name);
	fd = open(path, O_WRONLY);

	if (fd < 0)
		return -errno;
	len = snprintf(value, sizeof(value), "%u\n", count);
	ret = write(fd, value, len);
	ret = ret == len ? 0 : -errno;
	close(fd);
	return ret;
}

static int packed_writeback(unsigned int count)
{
	return packed_control("writeback", count);
}

static bool packed_wait_empty(void);

static bool packed_fixture(void)
{
	cpu_set_t pinned, saved;
	int cpu = sched_getcpu();
	bool valid;

	CPU_ZERO(&pinned);
	if (cpu < 0 || sched_getaffinity(0, sizeof(saved), &saved))
		return false;
	CPU_SET(cpu, &pinned);
	if (sched_setaffinity(0, sizeof(pinned), &pinned))
		return false;
	valid = !madvise(data, data_size, MADV_DONTNEED);
	visit_data(COMPRESSIBLE, 0, true);
	valid &= thp_pageout();
	return !sched_setaffinity(0, sizeof(saved), &saved) && valid;
}

static void *packed_writer(void *arg)
{
	int *ret = arg;

	*ret = packed_writeback(512);
	return NULL;
}

static void test_packed_swap(const char *device, bool fail_io)
{
	size_t swapped = 0, resident = 0;
	bool valid;
	long pages, bytes, errors;
	pthread_t thread;
	int ret, status;
	pid_t pid;

	ksft_set_plan(fail_io ? 7 : 6);
	if (fail_io) {
		valid = packed_fixture();
		errors = packed_stat("writeback_errors");
		valid &= packed_writeback(16) == -EIO;
		valid &= packed_stat("writeback_errors") == errors + 1;
		valid &= packed_wait_empty();
		valid &= visit_data(COMPRESSIBLE, 0, false);
		ksft_test_result(valid, "packed write error retains original payloads\n");
	}

	valid = packed_fixture() && !packed_writeback(512);
	pages = packed_stat("swap_pages");
	bytes = packed_stat("swapped_bytes");
	valid &= pages > 0 && pages < (long)nr_pages && bytes > 0;
	valid &= !snapshot(after, &swapped, &resident) && swapped == nr_pages;
	ksft_print_msg("packed pages=%ld payload_bytes=%ld token_pages=%zu\n",
		       pages, bytes, swapped);
	valid &= visit_data(COMPRESSIBLE, 0, false);
	valid &= packed_wait_empty() && packed_stat("swapped_bytes") == 0;
	ksft_test_result(valid, "packed disk fault restores every word and releases swap slots\n");

	valid = packed_fixture() && !packed_writeback(512);
	pid = fork();
	if (!pid) {
		bool child = visit_data(COMPRESSIBLE, 0, false);

		visit_data(COMPRESSIBLE, 1, true);
		_exit(child && visit_data(COMPRESSIBLE, 1, false) ? 0 : 1);
	}
	valid &= pid > 0;
	if (pid > 0)
		valid &= waitpid(pid, &status, 0) == pid &&
			 WIFEXITED(status) && !WEXITSTATUS(status);
	valid &= visit_data(COMPRESSIBLE, 0, false);
	valid &= packed_wait_empty();
	ksft_test_result(valid, "packed fork preserves COW data and slot lifetime\n");

	valid = packed_fixture();
	ret = -1;
	if (pthread_create(&thread, NULL, packed_writer, &ret)) {
		valid = false;
	} else {
		valid &= visit_data(COMPRESSIBLE, 0, false);
		valid &= !pthread_join(thread, NULL) && !ret;
	}
	valid &= packed_wait_empty();
	ksft_test_result(valid, "faults racing packed writeback preserve data\n");

	valid = packed_fixture();
	ret = -1;
	if (pthread_create(&thread, NULL, packed_writer, &ret)) {
		valid = false;
	} else {
		valid &= !madvise(data, data_size, MADV_DONTNEED);
		valid &= !pthread_join(thread, NULL) && !ret;
	}
	valid &= packed_wait_empty() && packed_stat("swapped_bytes") == 0;
	ksft_test_result(valid, "unmap racing packed writeback releases every slot\n");

	valid = packed_fixture() && !packed_writeback(512);
	valid &= packed_stat("swap_pages") > 0;
	ret = swapoff(device);
	ksft_print_msg("packed swapoff ret=%d errno=%d\n", ret, ret ? errno : 0);
	valid &= !ret && !swap_devices_present();
	valid &= packed_wait_empty() && packed_stat("swapped_bytes") == 0;
	valid &= !snapshot(after, &swapped, &resident) && swapped == nr_pages;
	valid &= visit_data(COMPRESSIBLE, 0, false);
	ksft_test_result(valid, "swapoff restores payloads and preserves token PTEs\n");

	valid = packed_fixture();
	valid &= packed_writeback(512) == -ENOSPC;
	valid &= visit_data(COMPRESSIBLE, 0, false);
	valid &= packed_wait_empty();
	ksft_test_result(valid, "writeback without swap retains original data\n");
}

static bool packed_writer_done;

static void *packed_swapoff_writer(void *arg)
{
	packed_writer(arg);
	__atomic_store_n(&packed_writer_done, true, __ATOMIC_RELEASE);
	return NULL;
}

static void packed_interrupt(int sig)
{
	(void)sig;
}

static void test_packed_swapoff(const char *device, bool fail_read)
{
	static const char cg[] = "/sys/fs/cgroup/memcompress-swapoff";
	char path[160];
	pthread_t thread;
	long written;
	bool valid, inflight = false;
	int ret, writer_ret = 0;
	unsigned int i;

	ksft_set_plan(fail_read ? 4 : 3);
	if (fail_read) {
		valid = packed_fixture() && !packed_writeback(512);
		errno = 0;
		ret = swapoff(device);
		ksft_print_msg("packed read-error swapoff ret=%d errno=%d\n", ret, errno);
		valid &= ret == -1 && errno == EIO && swap_devices_present();
		valid &= packed_stat("swap_pages") > 0;
		valid &= visit_data(COMPRESSIBLE, 0, false);
		valid &= packed_wait_empty();
		ksft_test_result(valid, "swapoff read error preserves backing and device\n");
	}

	valid = packed_fixture() && !packed_writeback(512);
	{
		pid_t pid = fork();
		int status;

		if (!pid) {
			struct sigaction action = { .sa_handler = packed_interrupt };
			struct itimerval timer = {
				.it_interval = { .tv_usec = 1000 },
				.it_value = { .tv_usec = 1000 },
			};
			bool interrupted;

			sigemptyset(&action.sa_mask);
			sigaction(SIGALRM, &action, NULL);
			setitimer(ITIMER_REAL, &timer, NULL);
			ret = swapoff(device);
			interrupted = ret == -1 && errno == EINTR;
			memset(&timer, 0, sizeof(timer));
			setitimer(ITIMER_REAL, &timer, NULL);
			_exit(interrupted ? 0 : 1);
		}
		valid &= pid > 0;
		if (pid > 0)
			valid &= waitpid(pid, &status, 0) == pid &&
				 WIFEXITED(status) && !WEXITSTATUS(status);
	}
	valid &= swap_devices_present() && packed_stat("swap_pages") > 0;
	valid &= visit_data(COMPRESSIBLE, 0, false);
	ksft_test_result(valid, "interrupted packed swapoff retains data and remaining slots\n");

	/* The harness throttles writes so a completed batch can precede in-flight I/O. */
	valid = packed_fixture();
	written = packed_stat("written_pages");
	packed_writer_done = false;
	if (pthread_create(&thread, NULL, packed_swapoff_writer, &writer_ret)) {
		valid = false;
	} else {
		for (i = 0; i < 5000; i++) {
			if (packed_stat("written_pages") > written &&
			    !__atomic_load_n(&packed_writer_done, __ATOMIC_ACQUIRE)) {
				inflight = true;
				break;
			}
			if (__atomic_load_n(&packed_writer_done, __ATOMIC_ACQUIRE))
				break;
			usleep(1000);
		}
		valid &= !swapoff(device);
		valid &= !pthread_join(thread, NULL);
		valid &= !writer_ret || writer_ret == -ENOSPC;
	}
	valid &= inflight && !swap_devices_present() && packed_wait_empty();
	valid &= visit_data(COMPRESSIBLE, 0, false);
	ksft_print_msg("packed swapoff overlap=%d writer_result=%d\n", inflight, writer_ret);
	ksft_test_result(valid, "swapoff joins in-flight packed batches and releases the device\n");

	valid = !swapon(device, 0);
	valid &= self_setting("/sys/fs/cgroup/cgroup.subtree_control", "+memory");
	valid &= !mkdir(cg, 0755);
	snprintf(path, sizeof(path), "%s/cgroup.procs", cg);
	valid &= self_setting(path, "0");
	valid &= packed_fixture() && !packed_writeback(512);
	/* Keep data charged to an empty cgroup; the test itself lives in the root. */
	valid &= self_setting("/sys/fs/cgroup/cgroup.procs", "0");
	snprintf(path, sizeof(path), "%s/memory.max", cg);
	valid &= self_setting(path, "0");
	errno = 0;
	ret = swapoff(device);
	ksft_print_msg("packed charge-error swapoff ret=%d errno=%d\n", ret, errno);
	valid &= ret == -1 && errno == ENOMEM && swap_devices_present();
	valid &= packed_stat("swap_pages") > 0;
	valid &= self_setting(path, "max");
	valid &= !swapoff(device);
	valid &= packed_wait_empty() && visit_data(COMPRESSIBLE, 0, false);
	valid &= !madvise(data, data_size, MADV_DONTNEED);
	valid &= !rmdir(cg);
	ksft_test_result(valid, "swapoff charge failure preserves tokens for a successful retry\n");
}

static bool packed_wait_empty(void)
{
	unsigned int i;

	for (i = 0; i < 5000; i++) {
		if (!packed_stat("swap_pages"))
			return true;
		usleep(1000);
	}
	return false;
}

static bool packed_wait_drain(void)
{
	unsigned int i;

	for (i = 0; i < 5000; i++) {
		if (!packed_stat("drain_pending") &&
		    (!packed_stat("lru_entries") || packed_stat("drain_error")))
			return true;
		usleep(1000);
	}
	return false;
}

static void *packed_defrag_thread(void *arg)
{
	int *result = arg;
	unsigned int i;

	for (i = 0; i < 4 && !*result; i++)
		*result = packed_control("defrag", 1);
	return NULL;
}

static void test_packed_maintenance(const char *device, bool fail_io)
{
	bool valid;
	long before_pages, after_pages, before_runs, before_bytes;
	pthread_t thread;
	int ret;
	size_t i;

	ksft_set_plan(fail_io ? 10 : 8);
	if (fail_io) {
		valid = packed_fixture() && !packed_control("drain", 16);
		valid &= packed_wait_drain() && packed_stat("drain_error") == -EIO;
		valid &= visit_data(COMPRESSIBLE, 0, false) && packed_wait_empty();
		ksft_test_result(valid, "delayed drain write error retains every payload\n");
	}

	valid = packed_fixture();
	for (i = 1; i < nr_pages; i += 2)
		valid &= __atomic_load_n(data + i * page_size / sizeof(*data), __ATOMIC_RELAXED) ==
			 (UINT64_C(0x6d656d636f6d7000) ^ i);
	before_pages = named_stat("/sys/kernel/mm/memcompress/debug_stat", "pool_bytes");
	valid &= !packed_control("defrag", 1);
	after_pages = named_stat("/sys/kernel/mm/memcompress/debug_stat", "pool_bytes");
	ksft_print_msg("RAM compaction pool_bytes=%ld -> %ld\n", before_pages, after_pages);
	valid &= before_pages > after_pages && after_pages > 0;
	valid &= visit_data(COMPRESSIBLE, 0, false);
	ksft_test_result(valid, "RAM compaction releases allocator pages and preserves data\n");

	valid = packed_fixture() && !packed_writeback(512);
	valid &= self_setting("/sys/kernel/mm/memcompress/enabled", "0");
	for (i = 1; i < nr_pages; i += 2)
		valid &= __atomic_load_n(data + i * page_size / sizeof(*data), __ATOMIC_RELAXED) ==
			 (UINT64_C(0x6d656d636f6d7000) ^ i);
	before_pages = packed_stat("swap_pages");
	before_bytes = packed_stat("swapped_bytes");
	before_runs = packed_stat("defrag_relocated");
	if (fail_io) {
		long errors = packed_stat("writeback_errors");

		valid &= packed_control("defrag", 1) == -EIO;
		valid &= packed_stat("writeback_errors") == errors + 1;
		valid &= before_bytes == packed_stat("swapped_bytes");
		ksft_test_result(valid, "defrag target write failure preserves source slots\n");
	}
	for (i = 0; i < 4; i++)
		valid &= !packed_control("defrag", 1);
	after_pages = packed_stat("swap_pages");
	ksft_print_msg("packed defrag pages=%ld -> %ld bytes=%ld -> %ld\n",
		       before_pages, after_pages, before_bytes, packed_stat("swapped_bytes"));
	valid &= before_pages > after_pages && after_pages > 0;
	valid &= before_bytes == packed_stat("swapped_bytes");
	valid &= packed_stat("defrag_relocated") > before_runs;
	valid &= visit_data(COMPRESSIBLE, 0, false) && packed_wait_empty();
	valid &= self_setting("/sys/kernel/mm/memcompress/enabled", "1");
	ksft_test_result(valid, "sparse packed pages consolidate without changing payloads\n");

	valid = packed_fixture() && !packed_writeback(512);
	before_pages = packed_stat("swap_pages");
	before_runs = packed_stat("defrag_relocated");
	for (i = 1; i < nr_pages; i += 2)
		valid &= __atomic_load_n(data + i * page_size / sizeof(*data), __ATOMIC_RELAXED) ==
			 (UINT64_C(0x6d656d636f6d7000) ^ i);
	for (i = 0; i < 5000 && packed_stat("defrag_relocated") == before_runs; i++)
		usleep(1000);
	valid &= packed_stat("defrag_relocated") > before_runs;
	valid &= packed_stat("swap_pages") < before_pages;
	valid &= visit_data(COMPRESSIBLE, 0, false) && packed_wait_empty();
	ksft_test_result(valid, "sparse-page release triggers background defragmentation\n");

	for (unsigned int unmap = 0; unmap < 2; unmap++) {
		valid = packed_fixture() && !packed_writeback(512);
		valid &= self_setting("/sys/kernel/mm/memcompress/enabled", "0");
		for (i = 1; i < nr_pages; i += 2)
			valid &= __atomic_load_n(data + i * page_size / sizeof(*data),
						__ATOMIC_RELAXED) ==
				 (UINT64_C(0x6d656d636f6d7000) ^ i);
		ret = 0;
		if (pthread_create(&thread, NULL, packed_defrag_thread, &ret)) {
			valid = false;
		} else {
			if (unmap)
				valid &= !madvise(data, data_size, MADV_DONTNEED);
			else
				valid &= visit_data(COMPRESSIBLE, 0, false);
			valid &= !pthread_join(thread, NULL) && !ret;
		}
		valid &= packed_wait_empty() && !packed_stat("swapped_bytes");
		valid &= self_setting("/sys/kernel/mm/memcompress/enabled", "1");
		ksft_test_result(valid, "%s racing defrag releases all source and target slots\n",
				 unmap ? "unmap" : "fault");
	}

	valid = packed_fixture();
	before_runs = packed_stat("drain_runs");
	valid &= !packed_control("drain", 512) && packed_wait_drain();
	valid &= packed_stat("drain_runs") > before_runs;
	valid &= packed_stat("swapped_bytes") > 0 && !packed_stat("drain_error");
	valid &= visit_data(COMPRESSIBLE, 0, false) && packed_wait_empty();
	ksft_test_result(valid, "delayed drain exhausts its bounded entry budget\n");

	valid = packed_fixture() && !packed_control("drain", 512);
	valid &= self_setting("/sys/kernel/mm/memcompress/enabled", "0");
	valid &= packed_stat("drain_pending") == 0;
	valid &= visit_data(COMPRESSIBLE, 0, false) && packed_wait_empty();
	valid &= self_setting("/sys/kernel/mm/memcompress/enabled", "1");
	ksft_test_result(valid, "disable joins maintenance workers and preserves data\n");

	valid = packed_fixture() && !swapoff(device);
	valid &= packed_control("drain", 512) == -ENOSPC;
	valid &= !packed_control("defrag", 1);
	valid &= visit_data(COMPRESSIBLE, 0, false) && packed_wait_empty();
	ksft_test_result(valid, "maintenance without swap retains compressed data\n");
}

static void usage(const char *program)
{
	printf("Usage: %s [--token-type N] [--strict-rollback] [--strict-smaps]\n"
	       "       [--thp-pages 4|8|16] [--thp-fail-alloc] [--help]\n",
	       program);
	printf("  --thp-pages N      Add THP tests; requires matching mTHP sysfs policy.\n");
	printf("  --thp-fail-alloc   Requires task-filtered order>0 fail_page_alloc setup.\n");
	printf("  --packed-swap DEV  Test packed I/O; removes the supplied active test swap.\n");
	printf("  --packed-maintenance Test compaction, defrag and delayed drain.\n");
	printf("  --packed-swapoff  Test in-flight swapoff and charge failure; needs cgroup v2.\n");
	printf("  --packed-fail-read Expect one disk read error in swapoff tests.\n");
	printf("  --packed-fail-io   Expect one injected error on the first packed write.\n");
	printf("Default: check data and COW; report PTE and smaps behavior.\n");
	printf("  --token-type N     Expected pagemap swap type, 0..31 (default 27).\n");
	printf("  --strict-rollback  Require rejected pages to remain resident.\n");
	printf("  --strict-smaps     Require Swap to track token PTEs and faults.\n");
	printf("Type 27 is confirmed for this vendor image and current op13 config.\n");
	printf("For other CONFIG settings, verify the type and override it.\n");
	printf("Tokens include PENDING pages and do not prove codec completion.\n");
	printf("Requires no configured swap; changes no global tunables.\n");
	printf("Data: 2 MiB, or 8 MiB with THP tests; fork doubles this; timeout: 45/180s.\n");
}

static bool parse_token_type(const char *value)
{
	unsigned long parsed;
	char *end;

	if (*value < '0' || *value > '9')
		return false;
	errno = 0;
	parsed = strtoul(value, &end, 10);
	if (errno || *end || parsed > PM_TYPE_MASK)
		return false;
	token_type = parsed;
	return true;
}

int main(int argc, char **argv)
{
	void *mapping;
	size_t mapping_size;
	int argument, ret;
	const char *packed_device = NULL;
	bool packed_fail_io = false, packed_swapoff = false, packed_fail_read = false;
	bool packed_maintenance = false;

	for (argument = 1; argument < argc; argument++) {
		if (!strcmp(argv[argument], "--packed-swap")) {
			if (++argument == argc)
				ksft_exit_fail_msg("--packed-swap requires a test swap device\n");
			packed_device = argv[argument];
		} else if (!strcmp(argv[argument], "--packed-maintenance"))
			packed_maintenance = true;
		else if (!strcmp(argv[argument], "--packed-swapoff"))
			packed_swapoff = true;
		else if (!strcmp(argv[argument], "--packed-fail-read"))
			packed_fail_read = true;
		else if (!strcmp(argv[argument], "--packed-fail-io"))
			packed_fail_io = true;
		else if (!strcmp(argv[argument], "--strict-rollback"))
			strict_rollback = true;
		else if (!strcmp(argv[argument], "--strict-smaps"))
			strict_smaps = true;
		else if (!strcmp(argv[argument], "--thp-fail-alloc"))
			thp_fail_alloc = true;
		else if (!strcmp(argv[argument], "--thp-pages")) {
			if (++argument == argc ||
			    (strcmp(argv[argument], "4") && strcmp(argv[argument], "8") &&
			     strcmp(argv[argument], "16")))
				ksft_exit_fail_msg("--thp-pages requires 4, 8 or 16\n");
			thp_pages = atoi(argv[argument]);
			data_size = 8UL * 1024 * 1024;
		} else if (!strcmp(argv[argument], "--token-type")) {
			if (++argument == argc || !parse_token_type(argv[argument])) {
				usage(argv[0]);
				return KSFT_FAIL;
			}
		} else {
			usage(argv[0]);
			return !strcmp(argv[argument], "--help") ? KSFT_PASS : KSFT_FAIL;
		}
	}
	if (thp_fail_alloc && !thp_pages)
		ksft_exit_fail_msg("--thp-fail-alloc requires --thp-pages\n");
	ksft_print_header();
	if (access("/sys/kernel/mm/memcompress/stat", R_OK))
		ksft_exit_skip("memcompress sysfs is unavailable\n");
	if (!packed_device && swap_devices_present())
		ksft_exit_skip("requires no configured swap devices for PTE attribution\n");
	ret = admission_status();
	if (ret == -EOPNOTSUPP || ret == -EACCES || ret == -EPERM)
		ksft_exit_skip("memcompress admission unavailable (%s)\n", strerror(-ret));
	if (ret < 0)
		ksft_exit_fail_msg("cannot read memcompress admission (%s)\n", strerror(-ret));
	if (!ret)
		ksft_print_msg("enabled node absent; admission unknown, requiring token PTEs\n");
	ksft_print_msg("strict rollback=%d strict smaps=%d\n", strict_rollback, strict_smaps);
	ksft_print_msg("memcompress token type=%u; tokens may still be PENDING\n", token_type);
	page_size = sysconf(_SC_PAGESIZE);
	if (page_size != 4096)
		ksft_exit_skip("memcompress tests require 4 KiB pages\n");
	nr_pages = data_size / page_size;
	pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
	if (pagemap_fd < 0)
		ksft_exit_skip("pagemap is unavailable\n");
	before = calloc(nr_pages, sizeof(*before));
	after = calloc(nr_pages, sizeof(*after));
	if (!before || !after)
		ksft_exit_fail_msg("cannot allocate pagemap snapshots\n");
	/* Guard VMAs prevent merging, making the smaps measurement unambiguous. */
	mapping_size = data_size + 2 * THP_ALIGN;
	mapping = mmap(NULL, mapping_size, PROT_NONE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mapping == MAP_FAILED)
		ksft_exit_fail_msg("mmap failed\n");
	data = (void *)(((uintptr_t)mapping + THP_ALIGN) & ~(THP_ALIGN - 1));
	if (mprotect(data, data_size, PROT_READ | PROT_WRITE) ||
	    madvise(data, data_size, MADV_NOHUGEPAGE))
		ksft_exit_skip("cannot prepare isolated base-page mapping\n");
	signal(SIGALRM, timeout_handler);
	signal(SIGPIPE, SIG_IGN);
	alarm(thp_pages || packed_device ? 180 : 45);
	if (packed_device) {
		if (packed_maintenance)
			test_packed_maintenance(packed_device, packed_fail_io);
		else if (packed_swapoff)
			test_packed_swapoff(packed_device, packed_fail_read);
		else
			test_packed_swap(packed_device, packed_fail_io);
		goto out;
	}
	ksft_set_plan(TEST_COUNT + (thp_pages ? 10 : 0) + thp_fail_alloc);
	test_roundtrip(SAMEFILL, "same-filled page roundtrip");
	test_roundtrip(COMPRESSIBLE, "compressible payload roundtrip");
	test_fork_cow();
	test_smaps();
	test_rejected_pages();
	if (thp_pages) {
		test_thp_access(false, false);
		test_thp_access(true, false);
		test_thp_access(false, true);
		test_thp_partial(false);
		test_thp_partial(true);
		if (!prepare_thp())
			ksft_test_result_fail("cannot prepare THP fork mapping\n");
		else
			test_fork_cow();
		test_thp_race(false);
		test_thp_race(true);
		test_thp_uffd();
		test_thp_write();
		if (thp_fail_alloc)
			test_thp_alloc_failure();
	}
out:
	alarm(0);
	munmap(mapping, mapping_size);
	free(before);
	free(after);
	close(pagemap_fd);
	if (!ksft_get_pass_cnt() && !ksft_get_fail_cnt()) {
		ksft_print_cnts();
		return KSFT_SKIP;
	}
	ksft_finished();
}
