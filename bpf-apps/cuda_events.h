// cuda_events.h - 事件数据结构
#define TASK_COMM_LEN 16
#define MAX_DETAILS_LEN 128

enum cuda_event_type {
    CUDA_EVENT_MALLOC = 0,
    CUDA_EVENT_FREE,
    CUDA_EVENT_MEMCPY,
    CUDA_EVENT_LAUNCH_KERNEL,
    CUDA_EVENT_STREAM_SYNC,
};

struct cuda_malloc_event {
    __u32 pid;                    // 进程 ID
    __u64 size;                   // 请求分配的大小
    void *device_addr;            // 分配到的设备地址
    __s32 ret;                    // 返回码 (cudaError_t)
    __u64 start_ns;               // 调用开始时间
    __u64 end_ns;                 // 调用结束时间
    char comm[TASK_COMM_LEN];     // 进程名
};
