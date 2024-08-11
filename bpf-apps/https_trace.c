#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <sys/socket.h>
#include <time.h>

#include "https_trace.h"
#include "https_trace.skel.h"

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

static volatile bool exiting = false;

static void sig_handler(int signo)
{
	exiting = true;
}

// 以可读格式打印字符数组
void print_chars(const char *array, size_t size)
{
	size_t trimmed_size = size;
	for (trimmed_size = size; trimmed_size > 0; trimmed_size--) {
		if (array[trimmed_size - 1] != 0) {
			break;
		}
	}
	for (size_t i = 0; i < trimmed_size; i++) {
		printf("%c", (unsigned char)array[i]);
	}
	printf("\n\n");
}

// 输出 HTTPS 请求和响应信息（注意：长度截断至MAX_BUF_LENGTH）
static void handle_event(void *ctx, int cpu, void *data, __u32 data_size)
{
	const struct event_t *e = data;
	if (e->len > 0) {
		printf("====================================\n");
		char buf[MAX_BUF_LENGTH + 1] = { 0 };
		memcpy(buf, e->buf, e->len);
		printf("%s\t%s\n\n", e->comm, e->rw ? "write" : "read");
		print_chars(buf, sizeof(buf));
	}
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

// 查找库的路径
char *find_library_path(const char *libname)
{
	char cmd[256];
	static char path[256];
	snprintf(cmd, sizeof(cmd), "ldconfig -p | grep %s", libname);
	FILE *fp = popen(cmd, "r");
	if (!fp) {
		fprintf(stderr, "Failed to run command: %s\n", cmd);
		return NULL;
	}

	// 格式: libssl3.so (libc6,x86-64) => /lib/x86_64-linux-gnu/libssl3.so
	if (fgets(path, sizeof(path) - 1, fp) != NULL) {
		char *p = strrchr(path, '>');
		if (p && *(p + 1) == ' ') {
			memmove(path, p + 2, strlen(p + 2) + 1);
			char *end = strchr(path, '\n');
			if (end) {
				*end = '\0';
			}
			pclose(fp);
			return path;
		}
	}

	pclose(fp);
	return NULL;
}

int main(int argc, char **argv)
{
	struct https_trace_bpf *skel;
	struct perf_buffer *pb = NULL;
	int err = 0;

	// 设置libbpf的错误和调试信息回调
	libbpf_set_print(libbpf_print_fn);

	// 注册信号处理程序
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// 提升RLIMIT_MEMLOCK以允许BPF子系统执行任何需要的操作
	bump_memlock_rlimit();

	// 查找OpenSSL库的路径
	char *libssl_path = find_library_path("libssl.so");
	if (!libssl_path) {
		fprintf(stderr, "Failed to find libssl.so\n");
		return 1;
	}

	// 加载BPF程序
	skel = https_trace_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	// 创建buffer并绑定事件处理回调
	pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 16,
			      handle_event, NULL, NULL, NULL);
	if (!pb) {
		fprintf(stderr, "Failed to create perf buffer\n");
		goto cleanup;
	}

	// 挂载uprobe到OpenSSL库
	printf("Attaching uprobe to %s\n", libssl_path);
	// SSL_read
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_ropts,.func_name = "SSL_read");
	skel->links.probe_SSL_read_entry =
	    bpf_program__attach_uprobe_opts(skel->progs.probe_SSL_read_entry,
					    -1, libssl_path, 0, &uprobe_ropts);
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_ropts_ret,.func_name =
		    "SSL_read",.retprobe = true);
	skel->links.probe_SSL_read_exit =
	    bpf_program__attach_uprobe_opts(skel->progs.probe_SSL_read_exit, -1,
					    libssl_path, 0, &uprobe_ropts_ret);
	// SSL_write
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_wopts,.func_name = "SSL_write");
	skel->links.probe_SSL_write_entry =
	    bpf_program__attach_uprobe_opts(skel->progs.probe_SSL_write_entry,
					    -1, libssl_path, 0, &uprobe_wopts);
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_wopts_ret,.func_name =
		    "SSL_write",.retprobe = true);
	skel->links.probe_SSL_write_exit =
	    bpf_program__attach_uprobe_opts(skel->progs.probe_SSL_write_exit,
					    -1, libssl_path, 0,
					    &uprobe_wopts_ret);

	// 从Buffer中读取数据
	printf("Tracing HTTPS traffic... Hit Ctrl-C to end.\n");
	while (!exiting) {
		err = perf_buffer__poll(pb, 100);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Error polling perf buffer: %d\n", err);
			break;
		}
	}

 cleanup:
	// 释放资源
	perf_buffer__free(pb);
	https_trace_bpf__destroy(skel);
	return -err;
}
