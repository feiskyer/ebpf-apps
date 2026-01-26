// test_cuda_malloc.c - 纯 C 版本，通过 dlopen 调用 cudaMalloc（无需 nvcc）
//
// 编译:
//   gcc -o test_cuda_malloc test_cuda_malloc.c -ldl
//
// 运行:
//   ./test_cuda_malloc [size] [count] [interval]
//
// 参数:
//   size     - 分配大小（字节），默认 1MB
//   count    - 调用次数，默认 5
//   interval - 调用间隔（秒），默认 1
//
// 示例:
//   ./test_cuda_malloc                      # 默认: 1MB, 5次, 间隔1秒
//   ./test_cuda_malloc 1048576 10 2         # 1MB, 10次, 间隔2秒
//
// 注意:
//   需要 libcudart.so 在 LD_LIBRARY_PATH 中，或者在 /usr/local/cuda/lib64/
//   export LD_LIBRARY_PATH=/usr/local/cuda/lib64:$LD_LIBRARY_PATH
//
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>

typedef int cudaError_t;
typedef cudaError_t (*cudaMalloc_t)(void **devPtr, size_t size);
typedef cudaError_t (*cudaFree_t)(void *devPtr);

int main(int argc, char **argv)
{
    void *handle;
    cudaMalloc_t cuda_malloc;
    cudaFree_t cuda_free;
    void *d_ptr;
    size_t size = 1024 * 1024;  // 1MB
    int count = 5;
    int interval = 1;

    // 解析参数
    if (argc > 1) size = atol(argv[1]);
    if (argc > 2) count = atoi(argv[2]);
    if (argc > 3) interval = atoi(argv[3]);

    printf("Testing cudaMalloc: size=%zu bytes, count=%d, interval=%ds\n",
           size, count, interval);
    printf("PID: %d\n\n", getpid());

    // 加载 libcudart.so
    handle = dlopen("libcudart.so", RTLD_NOW);
    if (!handle) {
        // 尝试其他路径
        handle = dlopen("/usr/local/cuda/lib64/libcudart.so", RTLD_NOW);
    }
    if (!handle) {
        fprintf(stderr, "Failed to load libcudart.so: %s\n", dlerror());
        fprintf(stderr, "Try: export LD_LIBRARY_PATH=/usr/local/cuda/lib64\n");
        return 1;
    }

    // 获取函数指针
    cuda_malloc = (cudaMalloc_t)dlsym(handle, "cudaMalloc");
    cuda_free = (cudaFree_t)dlsym(handle, "cudaFree");
    if (!cuda_malloc || !cuda_free) {
        fprintf(stderr, "Failed to find cudaMalloc/cudaFree: %s\n", dlerror());
        dlclose(handle);
        return 1;
    }

    printf("Loaded cudaMalloc at %p\n\n", (void *)cuda_malloc);

    // 测试调用
    for (int i = 0; i < count; i++) {
        printf("[%d] cudaMalloc(%zu)... ", i + 1, size);
        fflush(stdout);

        cudaError_t err = cuda_malloc(&d_ptr, size);
        if (err != 0) {
            printf("FAILED: error=%d\n", err);
        } else {
            printf("OK, ptr=%p\n", d_ptr);
            cuda_free(d_ptr);
        }

        if (i < count - 1) {
            sleep(interval);
        }
    }

    printf("\nDone.\n");
    dlclose(handle);
    return 0;
}
