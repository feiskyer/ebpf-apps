// This is a Hello World example with C.
// Source: BPF Performance Tools
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <linux/version.h>
#include <bpf/bpf.h>
#include <bcc/libbpf.h>

#define DEBUGFS	"/sys/kernel/debug/tracing"

char bpf_log_buf[BPF_LOG_BUF_SIZE];

int main()
{
	int prog_fd, probe_fd;

	struct bpf_insn prog[] = {
		BPF_MOV64_IMM(BPF_REG_1, 0xa21),	/* '!\n' */
		BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, -4),
		BPF_MOV64_IMM(BPF_REG_1, 0x646c726f),	/* 'orld' */
		BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, -8),
		BPF_MOV64_IMM(BPF_REG_1, 0x57202c6f),	/* 'o, W' */
		BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, -12),
		BPF_MOV64_IMM(BPF_REG_1, 0x6c6c6548),	/* 'Hell' */
		BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, -16),
		BPF_MOV64_IMM(BPF_REG_1, 0),
		BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1, -2),
		BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -16),
		BPF_MOV64_IMM(BPF_REG_2, 15),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
			     BPF_FUNC_trace_printk),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	size_t insns_cnt = sizeof(prog) / sizeof(struct bpf_insn);

	prog_fd = bpf_load_program(BPF_PROG_TYPE_KPROBE,
				   prog,
				   insns_cnt,
				   "GPL",
				   LINUX_VERSION_CODE,
				   bpf_log_buf, BPF_LOG_BUF_SIZE);
	if (prog_fd < 0) {
		printf("ERROR: failed to load prog '%s'\n", strerror(errno));
		return 1;
	}

	probe_fd =
	    bpf_attach_kprobe(prog_fd, BPF_PROBE_ENTRY, "hello_world",
			      "do_nanosleep", 0, 0);
	if (prog_fd < 0) {
		return 2;
	}

	system("cat " DEBUGFS "/trace_pipe");
	close(probe_fd);
	bpf_detach_kprobe("hello_world");
	close(prog_fd);
	return 0;
}
