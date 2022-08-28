/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Facebook */
/* Refer https://github.com/iovisor/bcc/blob/master/libbpf-tools/bashreadline.c */
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "bashreadline.h"
#include "bashreadline.skel.h"
#include "uprobe_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static bool verbose = false;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_size)
{
	struct str_t *e = (struct str_t *)data;
	struct tm *tm;
	char ts[16];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%m:%S", tm);

	printf("%-9s %-7d %s\n", ts, e->pid, e->str);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	struct bashreadline_bpf *obj = NULL;
	struct perf_buffer *pb = NULL;
	off_t func_off;
	int err = 0;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	obj = bashreadline_bpf__open_and_load();
	if (!obj) {
		warn("failed to open and load BPF object\n");
		goto cleanup;
	}

	func_off = get_elf_func_offset("/usr/bin/bash", "readline");
	if (func_off < 0) {
		warn("cound not find readline in bash\n");
		goto cleanup;
	}

	obj->links.printret =
	    bpf_program__attach_uprobe(obj->progs.printret, true, -1,
				       "/usr/bin/bash", func_off);
	if (!obj->links.printret) {
		err = -errno;
		warn("failed to attach readline: %d\n", err);
		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES, handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	printf("%-9s %-7s %s\n", "TIME", "PID", "COMMAND");

	/* Main polling loop */
	while ((err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS)) >= 0) ;
	printf("Error polling perf buffer: %d\n", err);

 cleanup:
	perf_buffer__free(pb);
	bashreadline_bpf__destroy(obj);

	return err != 0;
}
