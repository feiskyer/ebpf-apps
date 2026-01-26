// cuda_events.c - 用户态程序，追踪 CUDA 内存分配
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <time.h>
#include <getopt.h>

#include "cuda_events.h"
#include "cuda_events.skel.h"

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

// 将 cudaError_t 转换为可读字符串
static const char *cuda_error_string(int err)
{
	switch (err) {
	case 0:
		return "cudaSuccess";
	case 1:
		return "cudaErrorInvalidValue";
	case 2:
		return "cudaErrorMemoryAllocation";
	default:
		return "cudaErrorUnknown";
	}
}

// 格式化字节大小为人类可读格式
static void format_size(char *buf, size_t buflen, __u64 size)
{
	if (size >= 1024 * 1024 * 1024) {
		snprintf(buf, buflen, "%.2f GB", (double)size / (1024 * 1024 * 1024));
	} else if (size >= 1024 * 1024) {
		snprintf(buf, buflen, "%.2f MB", (double)size / (1024 * 1024));
	} else if (size >= 1024) {
		snprintf(buf, buflen, "%.2f KB", (double)size / 1024);
	} else {
		snprintf(buf, buflen, "%llu B", size);
	}
}

// ring buffer 事件处理回调
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct cuda_malloc_event *e = data;
	char size_buf[32];
	double latency_us = (e->end_ns - e->start_ns) / 1000.0;

	format_size(size_buf, sizeof(size_buf), e->size);

	printf("%-16s %-7d %-12s %-18p %-15s %.2f us\n",
	       e->comm,
	       e->pid,
	       size_buf,
	       e->device_addr,
	       cuda_error_string(e->ret),
	       latency_us);

	return 0;
}

// 提升 RLIMIT_MEMLOCK 以允许 BPF 子系统执行任何需要的操作
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

// 常见的 CUDA 库路径
static const char *cuda_search_paths[] = {
	"/usr/local/cuda/lib64/libcudart.so",
	"/usr/local/cuda-12/lib64/libcudart.so",
	"/usr/local/cuda-11/lib64/libcudart.so",
	"/usr/lib/x86_64-linux-gnu/libcudart.so",
	"/usr/lib64/libcudart.so",
	NULL
};

// 查找库的路径
static char *find_library_path(const char *libname)
{
	char cmd[256];
	static char path[512];

	// 方法 1: 检查 CUDA_HOME 环境变量
	char *cuda_home = getenv("CUDA_HOME");
	if (cuda_home) {
		snprintf(path, sizeof(path), "%s/lib64/%s", cuda_home, libname);
		if (access(path, F_OK) == 0) {
			return path;
		}
	}

	// 方法 2: 检查 LD_LIBRARY_PATH
	char *ld_path = getenv("LD_LIBRARY_PATH");
	if (ld_path) {
		char *ld_copy = strdup(ld_path);
		char *dir = strtok(ld_copy, ":");
		while (dir) {
			snprintf(path, sizeof(path), "%s/%s", dir, libname);
			if (access(path, F_OK) == 0) {
				free(ld_copy);
				return path;
			}
			dir = strtok(NULL, ":");
		}
		free(ld_copy);
	}

	// 方法 3: 检查常见路径
	for (int i = 0; cuda_search_paths[i]; i++) {
		if (access(cuda_search_paths[i], F_OK) == 0) {
			strncpy(path, cuda_search_paths[i], sizeof(path) - 1);
			return path;
		}
	}

	// 方法 4: 使用 ldconfig
	snprintf(cmd, sizeof(cmd), "ldconfig -p 2>/dev/null | grep %s", libname);
	FILE *fp = popen(cmd, "r");
	if (fp) {
		// 格式: libcudart.so.xx (libc6,x86-64) => /path/to/libcudart.so.xx
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
	}

	return NULL;
}

static void print_usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [OPTIONS]\n", prog);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -l PATH    Path to libcudart.so\n");
	fprintf(stderr, "  -h         Show this help\n");
	fprintf(stderr, "\nExample:\n");
	fprintf(stderr, "  %s -l /usr/local/cuda/lib64/libcudart.so\n", prog);
}

int main(int argc, char **argv)
{
	struct cuda_events_bpf *skel;
	struct ring_buffer *rb = NULL;
	char *libcudart_path = NULL;
	int err = 0;
	int opt;

	// 解析命令行参数
	while ((opt = getopt(argc, argv, "l:h")) != -1) {
		switch (opt) {
		case 'l':
			libcudart_path = optarg;
			break;
		case 'h':
		default:
			print_usage(argv[0]);
			return opt == 'h' ? 0 : 1;
		}
	}

	// 设置 libbpf 的错误和调试信息回调
	libbpf_set_print(libbpf_print_fn);

	// 注册信号处理程序
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// 提升 RLIMIT_MEMLOCK
	bump_memlock_rlimit();

	// 查找 CUDA 运行时库的路径
	if (!libcudart_path) {
		libcudart_path = find_library_path("libcudart.so");
	}
	if (!libcudart_path) {
		fprintf(stderr, "Error: Failed to find libcudart.so\n\n");
		fprintf(stderr, "Searched locations:\n");
		fprintf(stderr, "  - CUDA_HOME environment variable\n");
		fprintf(stderr, "  - LD_LIBRARY_PATH directories\n");
		for (int i = 0; cuda_search_paths[i]; i++) {
			fprintf(stderr, "  - %s\n", cuda_search_paths[i]);
		}
		fprintf(stderr, "  - ldconfig cache\n\n");
		fprintf(stderr, "Solutions:\n");
		fprintf(stderr, "  1. Install CUDA Toolkit\n");
		fprintf(stderr, "  2. Set CUDA_HOME environment variable\n");
		fprintf(stderr, "  3. Use -l option to specify path manually:\n");
		fprintf(stderr, "     %s -l /path/to/libcudart.so\n", argv[0]);
		return 1;
	}

	// 验证文件存在
	if (access(libcudart_path, F_OK) != 0) {
		fprintf(stderr, "Error: %s does not exist\n", libcudart_path);
		return 1;
	}
	printf("Using CUDA runtime library: %s\n", libcudart_path);

	// 加载 BPF 程序
	skel = cuda_events_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	// 创建 ring buffer 并绑定事件处理回调
	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event,
			      NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	// 附加 uprobe 到 cudaMalloc 入口
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts, .func_name = "cudaMalloc");
	skel->links.trace_cuda_malloc =
	    bpf_program__attach_uprobe_opts(skel->progs.trace_cuda_malloc,
					    -1, libcudart_path, 0, &uprobe_opts);
	if (!skel->links.trace_cuda_malloc) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe to cudaMalloc: %d\n", err);
		goto cleanup;
	}

	// 附加 uretprobe 到 cudaMalloc 返回
	LIBBPF_OPTS(bpf_uprobe_opts, uretprobe_opts,
		    .func_name = "cudaMalloc",
		    .retprobe = true);
	skel->links.trace_cuda_malloc_ret =
	    bpf_program__attach_uprobe_opts(skel->progs.trace_cuda_malloc_ret,
					    -1, libcudart_path, 0, &uretprobe_opts);
	if (!skel->links.trace_cuda_malloc_ret) {
		err = -errno;
		fprintf(stderr, "Failed to attach uretprobe to cudaMalloc: %d\n", err);
		goto cleanup;
	}

	// 打印表头
	printf("\nTracing cudaMalloc calls... Hit Ctrl-C to end.\n");
	printf("%-16s %-7s %-12s %-18s %-15s %s\n",
	       "COMM", "PID", "SIZE", "DEVICE_ADDR", "RESULT", "LATENCY");
	printf("%-16s %-7s %-12s %-18s %-15s %s\n",
	       "----------------", "-------", "------------",
	       "------------------", "---------------", "----------");

	// 从 ring buffer 中读取数据
	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
	}

	printf("\nExiting...\n");

cleanup:
	// 释放资源
	ring_buffer__free(rb);
	cuda_events_bpf__destroy(skel);
	return -err;
}
