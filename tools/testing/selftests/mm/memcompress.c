// SPDX-License-Identifier: GPL-2.0-only
/*
 * Bounded memcompress data-integrity and failed-admission regression tests.
 *
 * Only this process's anonymous mapping is reclaimed, using MADV_PAGEOUT.
 * No global tunable is changed. Test data uses 2 MiB, at most 4 MiB after
 * fork COW. Run on a memcompress kernel with no configured swap devices;
 * otherwise pagemap cannot identify this private swap type portably.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../kselftest.h"

#define DATA_SIZE (2UL * 1024 * 1024)
#define PM_PRESENT (1ULL << 63)
#define PM_SWAP (1ULL << 62)
#define PM_FRAME_MASK ((1ULL << 55) - 1)
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
static bool compression_seen;

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

static bool admission_enabled(void)
{
	FILE *file = fopen("/sys/kernel/mm/memcompress/enabled", "r");
	int value;

	if (!file)
		return false;
	value = fgetc(file);
	fclose(file);
	return value == 'Y' || value == '1';
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
	int type = -1;

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
			return -EIO;
		/* Swap type and token are redacted without CAP_SYS_ADMIN. */
		if (!(entry & PM_FRAME_MASK))
			return -EACCES;
		if (!(entry & (PM_FRAME_MASK & ~31ULL)))
			return -EIO;
		if (type >= 0 && type != (int)(entry & 31))
			return -EAGAIN;
		type = entry & 31;
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
				   end == (uintptr_t)data + DATA_SIZE;
		} else if (selected && sscanf(line, "Swap: %llu kB", swap_kb) == 1) {
			ret = 0;
			break;
		}
	}
	fclose(file);
	return ret;
}

/* A pass requires stable, visible swap PTEs on this mapping with no disk swap. */
static int pageout_and_observe(size_t *swapped)
{
	size_t resident, second_swapped;
	unsigned int attempt;
	int ret;

	for (attempt = 0; attempt < 3; attempt++) {
		if (!admission_enabled())
			return -EOPNOTSUPP;
		if (madvise(data, DATA_SIZE, MADV_PAGEOUT))
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
			compression_seen = true;
			return 0;
		}
	}
	return -EAGAIN;
}

static void observation_failed(int ret, const char *name)
{
	if (ret == -EIO)
		ksft_test_result_fail("%s: invalid or unreadable pagemap\n", name);
	else
		ksft_test_result_skip("%s: cannot establish compression (%s)\n",
				      name, strerror(-ret));
}

static void test_roundtrip(enum pattern pattern, const char *name)
{
	size_t swapped;
	int ret;

	visit_data(pattern, 0, true);
	ret = pageout_and_observe(&swapped);
	if (ret) {
		observation_failed(ret, name);
		return;
	}
	ksft_test_result(visit_data(pattern, 0, false),
			 "%s: %zu compressed PTEs\n", name, swapped);
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
	const char *name = "fork compressed PTEs and isolate parent/child writes";
	int child_ready[2], parent_ready[2], status, ret;
	size_t swapped;
	bool valid;
	pid_t child;

	visit_data(COMPRESSIBLE, 0, true);
	ret = pageout_and_observe(&swapped);
	if (ret) {
		observation_failed(ret, name);
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
		ksft_test_result(valid, "%s: %zu compressed PTEs\n", name, swapped);
	}
	close(child_ready[0]);
	close(parent_ready[1]);
}

static void test_smaps(void)
{
	const char *name = "smaps Swap agrees with compressed PTEs and faults";
	unsigned long long swap_kb;
	size_t swapped, resident, second_swapped;
	bool valid;
	int ret;

	visit_data(COMPRESSIBLE, 3, true);
	ret = pageout_and_observe(&swapped);
	if (ret) {
		observation_failed(ret, name);
		return;
	}
	ret = mapping_swap_kb(&swap_kb);
	if (ret) {
		ksft_test_result_skip("%s: smaps mapping unavailable\n", name);
		return;
	}
	ret = snapshot(after, &second_swapped, &resident);
	if (ret) {
		observation_failed(ret, name);
		return;
	}
	if (swapped != second_swapped ||
	    memcmp(before, after, nr_pages * sizeof(*before))) {
		ksft_test_result_skip("%s: mapping changed during observation\n", name);
		return;
	}
	valid = swap_kb == swapped * (page_size / 1024);
	valid &= visit_data(COMPRESSIBLE, 3, false);
	if (!valid) {
		ksft_test_result_fail("%s: Swap count or restored data mismatch\n", name);
		return;
	}
	ret = snapshot(after, &second_swapped, &resident);
	if (ret) {
		observation_failed(ret, name);
		return;
	}
	if (second_swapped) {
		ksft_test_result_skip("%s: mapping reclaimed again after faults\n", name);
		return;
	}
	valid &= resident == nr_pages;
	valid &= !mapping_swap_kb(&swap_kb) && !swap_kb;
	ksft_test_result(valid, "%s: %zu pages\n", name, swapped);
}

static void test_rejected_pages(void)
{
	const char *name = "repeated incompressible pageout restores resident PTEs";
	unsigned long long swap_kb;
	size_t swapped, resident;
	unsigned int round;
	bool valid = true;
	int ret;

	if (!compression_seen || !admission_enabled()) {
		ksft_test_result_skip("%s: no successful compression control\n", name);
		return;
	}
	for (round = 0; round < 3; round++) {
		visit_data(RANDOM, round, true);
		if (madvise(data, DATA_SIZE, MADV_PAGEOUT)) {
			ksft_test_result_skip("%s: MADV_PAGEOUT failed (%s)\n",
					      name, strerror(errno));
			return;
		}
		ret = snapshot(before, &swapped, &resident);
		if (ret) {
			observation_failed(ret, name);
			return;
		}
		/* Check before reading: a read would hide a leaked PENDING PTE. */
		valid &= !swapped && resident == nr_pages;
		valid &= !mapping_swap_kb(&swap_kb) && !swap_kb;
		valid &= visit_data(RANDOM, round, false);
		if (!valid) {
			ksft_test_result_fail("%s: PTE, Swap or data mismatch in round %u\n",
					      name, round + 1);
			return;
		}
		if (!admission_enabled()) {
			ksft_test_result_skip("%s: admission disabled during test\n", name);
			return;
		}
	}
	ksft_test_result(valid, "%s: three rounds\n", name);
}

int main(void)
{
	void *mapping;
	size_t mapping_size;

	ksft_print_header();
	if (access("/sys/kernel/mm/memcompress/stat", R_OK))
		ksft_exit_skip("memcompress sysfs is unavailable\n");
	if (swap_devices_present())
		ksft_exit_skip("requires no configured swap devices for PTE attribution\n");
	if (!admission_enabled())
		ksft_exit_skip("memcompress admission is disabled\n");
	page_size = sysconf(_SC_PAGESIZE);
	if (page_size != 4096)
		ksft_exit_skip("memcompress tests require 4 KiB pages\n");
	nr_pages = DATA_SIZE / page_size;
	pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
	if (pagemap_fd < 0)
		ksft_exit_skip("pagemap is unavailable\n");
	before = calloc(nr_pages, sizeof(*before));
	after = calloc(nr_pages, sizeof(*after));
	if (!before || !after)
		ksft_exit_fail_msg("cannot allocate pagemap snapshots\n");
	/* Guard VMAs prevent merging, making the smaps measurement unambiguous. */
	mapping_size = DATA_SIZE + 2 * page_size;
	mapping = mmap(NULL, mapping_size, PROT_NONE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mapping == MAP_FAILED)
		ksft_exit_fail_msg("mmap failed\n");
	data = (void *)((char *)mapping + page_size);
	if (mprotect(data, DATA_SIZE, PROT_READ | PROT_WRITE) ||
	    madvise(data, DATA_SIZE, MADV_NOHUGEPAGE))
		ksft_exit_skip("cannot prepare isolated base-page mapping\n");
	signal(SIGALRM, timeout_handler);
	signal(SIGPIPE, SIG_IGN);
	alarm(45);
	ksft_set_plan(TEST_COUNT);
	test_roundtrip(SAMEFILL, "same-filled page roundtrip");
	test_roundtrip(COMPRESSIBLE, "compressed payload roundtrip");
	test_fork_cow();
	test_smaps();
	test_rejected_pages();
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
