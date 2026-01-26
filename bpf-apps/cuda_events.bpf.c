#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "cuda_events.h"

// Ring buffer 用于向用户态发送事件
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// 用于在 uprobe 和 uretprobe 之间传递参数
struct malloc_args {
    void **dev_ptr;
    size_t size;
    __u64 start_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct malloc_args);
} malloc_args_map SEC(".maps");

// 1) uprobe: 在 cudaMalloc 入口捕获参数
SEC("uprobe/cudaMalloc")
int trace_cuda_malloc(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // 捕获函数参数
    // cudaMalloc 签名: cudaError_t cudaMalloc(void **devPtr, size_t size)
    void **dev_ptr = (void **)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM2(ctx);

    // 保存参数供 uretprobe 使用
    struct malloc_args args = {
        .dev_ptr = dev_ptr,
        .size = size,
        .start_ns = bpf_ktime_get_ns(),
    };
    bpf_map_update_elem(&malloc_args_map, &pid, &args, BPF_ANY);

    return 0;
}

// 2) uretprobe: 在 cudaMalloc 返回时捕获结果
SEC("uretprobe/cudaMalloc")
int trace_cuda_malloc_ret(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // 获取之前保存的参数
    struct malloc_args *args = bpf_map_lookup_elem(&malloc_args_map, &pid);
    if (!args)
        return 0;

    // 从用户空间读取实际分配的设备地址
    void *device_addr;
    if (bpf_probe_read_user(&device_addr, sizeof(void *), args->dev_ptr) < 0)
        device_addr = NULL;

    // 准备事件数据
    struct cuda_malloc_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = pid;
    e->size = args->size;
    e->device_addr = device_addr;
    e->ret = (int)PT_REGS_RC(ctx);  // cudaError_t 返回值
    e->start_ns = args->start_ns;
    e->end_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 发送事件到用户态
    bpf_ringbuf_submit(e, 0);

    // 清理临时数据
    bpf_map_delete_elem(&malloc_args_map, &pid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
