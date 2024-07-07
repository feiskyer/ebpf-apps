#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <sys/socket.h>
#include <time.h>

#include "http_trace.h"
#include "http_trace.skel.h"

// 用于打印调试信息
static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
#ifdef DEBUGBPF
	return vfprintf(stderr, format, args);
#else
	return 0;
#endif
}

// 创建原始套接字
static inline int open_raw_sock(const char *name)
{
	struct sockaddr_ll sll;
	int sock;

	sock =
	    socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
		   htons(ETH_P_ALL));
	if (sock < 0) {
		printf("cannot create raw socket\n");
		return -1;
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = if_nametoindex(name);
	sll.sll_protocol = htons(ETH_P_ALL);
	if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		printf("bind to %s: %s\n", name, strerror(errno));
		close(sock);
		return -1;
	}

	return sock;
}

// 输出 HTTP 请求和响应信息（注意：长度截断至MAX_LENGTH）
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event_t *e = data;
	char saddr[16] = { }, daddr[16] = { };

	inet_ntop(AF_INET, &e->saddr, saddr, sizeof(saddr));
	inet_ntop(AF_INET, &e->daddr, daddr, sizeof(daddr));
	printf("%s:%d -> %s:%d (length: %d)\n%s\n\n", saddr, e->sport, daddr,
	       e->dport, e->payload_length, e->payload);
	return 0;
}

// 提升RLIMIT_MEMLOCK以允许BPF子系统执行任何需要的操作
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
	struct http_trace_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err = 0;

	// 设置libbpf的错误和调试信息回调
	libbpf_set_print(libbpf_print_fn);

	// 提升RLIMIT_MEMLOCK以允许BPF子系统执行任何需要的操作
	bump_memlock_rlimit();

	// 加载BPF程序
	skel = http_trace_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}
	// 创建ring buffer并绑定事件处理回调
	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event,
			      NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}
	// 将eBPF程序挂载到原始套接字
	int sock = open_raw_sock("eth0");
	if (sock < 0) {
		fprintf(stderr, "Failed to open raw socket\n");
		goto cleanup;
	}
	int prog_fd = bpf_program__fd(skel->progs.http_trace);
	if (setsockopt
	    (sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd))) {
		fprintf(stderr, "Failed to attach eBPF prog\n");
		goto cleanup;
	}
	// 从ring buffer中读取数据
	printf("Tracing HTTP traffic... Hit Ctrl-C to end.\n");
	while ((err = ring_buffer__poll(rb, 100)) >= 0) ;
	printf("Error polling perf buffer: %d\n", err);

 cleanup:
	// 释放资源
	ring_buffer__free(rb);
	http_trace_bpf__destroy(skel);
	return err != 0;
}
