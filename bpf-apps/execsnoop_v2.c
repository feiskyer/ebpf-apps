// Based on execsnoop(8) from BCC by Brendan Gregg and others.
// Refer https://github.com/iovisor/bcc/blob/master/libbpf-tools/execsnoop.c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <time.h>
#include "execsnoop_v2.h"
#include "execsnoop_v2.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
#ifdef DEBUGBPF
	return vfprintf(stderr, format, args);
#else
	return 0;
#endif
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static void inline quoted_symbol(char c)
{
	switch (c) {
	case '"':
		putchar('\\');
		putchar('"');
		break;
	case '\t':
		putchar('\\');
		putchar('t');
		break;
	case '\n':
		putchar('\\');
		putchar('n');
		break;
	default:
		putchar(c);
		break;
	}
}

static void print_args(const struct event *e, bool quote)
{
	int args_counter = 0;

	if (quote)
		putchar('"');

	for (int i = 0; i < e->args_size && args_counter < e->args_count; i++) {
		char c = e->args[i];
		if (quote) {
			if (c == '\0') {
				args_counter++;
				putchar('"');
				putchar(' ');
				if (args_counter < e->args_count) {
					putchar('"');
				}
			} else {
				quoted_symbol(c);
			}
		} else {
			if (c == '\0') {
				args_counter++;
				putchar(' ');
			} else {
				putchar(c);
			}
		}
	}
	if (e->args_count > TOTAL_MAX_ARGS) {
		fputs(" ...", stdout);
	}
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	time_t t;
	struct tm *tm;
	char ts[32];

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-16s %-6d %-6d %3d ", e->comm, e->pid, e->ppid, e->retval);
	print_args(e, true);
	putchar('\n');
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

int main(int argc, char **argv)
{
	struct execsnoop_v2_bpf *skel;
	struct perf_buffer *pb = NULL;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
	bump_memlock_rlimit();

	/* Open BPF application */
	skel = execsnoop_v2_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = execsnoop_v2_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoint handler */
	err = execsnoop_v2_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 64, handle_event, handle_lost_events, NULL, NULL);
	err = libbpf_get_error(pb);
	if (err) {
		pb = NULL;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	printf("Successfully started!\n");

	/* main: poll */
	while ((err = perf_buffer__poll(pb, 100)) >= 0) ;
	printf("Error polling perf buffer: %d\n", err);

 cleanup:
	perf_buffer__free(pb);
	execsnoop_v2_bpf__destroy(skel);
	return err != 0;
}
