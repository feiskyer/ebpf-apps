/* SPDX-License-Identifier: GPL-2.0 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "https_trace.h"

// 用户态和内核态的数据缓冲区
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 1024);
}
events SEC(".maps");

// 用于存储大量数据的缓冲区（避免在BPF程序中分配大量内存）
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct event_t);
	 __uint(max_entries, 1);
} data_buffer_heap SEC(".maps");

// 用于存储SSL读写缓冲区的哈希映射
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u64);
} bufs SEC(".maps");

// 存储SSL读写缓冲区的地址到哈希映射
static int SSL_rw_entry(struct pt_regs *ctx, void *ssl, void *buf, int num)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tid = (u32) pid_tgid;
	bpf_map_update_elem(&bufs, &tid, (u64 *) & buf, BPF_ANY);
	return 0;
}

static int SSL_rw_exit(struct pt_regs *ctx, int rw)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;
	u32 tid = (u32) pid_tgid;

	// 从哈希映射中读取SSL读写缓冲区的地址
	u64 *bufp = bpf_map_lookup_elem(&bufs, &tid);
	if (!bufp) {
		return 0;
	}
	// 从寄存器中读取函数调用的返回值
	int len = PT_REGS_RC(ctx);
	if (len <= 0) {
		return 0;
	}
	// 分配一个数据缓冲区
	__u32 zero = 0;
	struct event_t *event = bpf_map_lookup_elem(&data_buffer_heap, &zero);
	if (!event) {
		return 0;
	}

	event->rw = rw;
	event->pid = pid;
	event->uid = bpf_get_current_uid_gid();
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	// 读取SSL读写缓冲区的数据
	event->len =
	    (size_t)MAX_BUF_LENGTH <
	    (size_t)len ? (size_t)MAX_BUF_LENGTH : (size_t)len;
	if (bufp != NULL) {
		bpf_probe_read_user(event->buf, event->len,
				    (const char *)*bufp);
	}
	// 将数据缓冲区的数据发送到perf event
	bpf_map_delete_elem(&bufs, &tid);
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
			      sizeof(struct event_t));
	return 0;
}

SEC("uprobe/SSL_read")
int BPF_UPROBE(probe_SSL_read_entry, void *ssl, void *buf, int num)
{
	return SSL_rw_entry(ctx, ssl, buf, num);
}

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(probe_SSL_read_exit)
{
	return SSL_rw_exit(ctx, 0);
}

SEC("uprobe/SSL_write")
int BPF_UPROBE(probe_SSL_write_entry, void *ssl, void *buf, int num)
{
	return SSL_rw_entry(ctx, ssl, buf, num);
}

SEC("uretprobe/SSL_write")
int BPF_URETPROBE(probe_SSL_write_exit)
{
	return SSL_rw_exit(ctx, 1);
}

char _license[] SEC("license") = "Dual BSD/GPL";
