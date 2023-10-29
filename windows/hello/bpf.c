#include "bpf_helpers.h"

SEC("bind")
int hello(bind_md_t *ctx)
{
    bpf_printk("Hello, world!");
    return 0;
}