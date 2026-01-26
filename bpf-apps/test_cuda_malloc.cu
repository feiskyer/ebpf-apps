// test_cuda_malloc.cu - 简单测试程序，触发 cudaMalloc 调用
//
// 编译:
//   nvcc -o test_cuda_malloc_nvcc test_cuda_malloc.cu
//
// 运行:
//   ./test_cuda_malloc_nvcc [size] [count] [interval]
//
// 参数:
//   size     - 分配大小（字节），默认 1MB
//   count    - 调用次数，默认 5
//   interval - 调用间隔（秒），默认 1
//
// 示例:
//   ./test_cuda_malloc_nvcc                 # 默认: 1MB, 5次, 间隔1秒
//   ./test_cuda_malloc_nvcc 1048576 10 2    # 1MB, 10次, 间隔2秒
//
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <cuda_runtime.h>

int main(int argc, char **argv)
{
    void *d_ptr;
    size_t size = 1024 * 1024;  // 1MB
    int count = 5;
    int interval = 1;  // 秒

    if (argc > 1) size = atol(argv[1]);
    if (argc > 2) count = atoi(argv[2]);
    if (argc > 3) interval = atoi(argv[3]);

    printf("Testing cudaMalloc: size=%zu bytes, count=%d, interval=%ds\n",
           size, count, interval);
    printf("PID: %d\n\n", getpid());

    for (int i = 0; i < count; i++) {
        printf("[%d] cudaMalloc(%zu)... ", i + 1, size);
        fflush(stdout);

        cudaError_t err = cudaMalloc(&d_ptr, size);
        if (err != cudaSuccess) {
            printf("FAILED: %s\n", cudaGetErrorString(err));
        } else {
            printf("OK, ptr=%p\n", d_ptr);
            cudaFree(d_ptr);
        }

        if (i < count - 1) {
            sleep(interval);
        }
    }

    printf("\nDone.\n");
    return 0;
}
