#include "bpf_helpers.h"

SEC("bind")
int func(bind_md_t *ctx)
{
    bpf_printk("Hello, world!");
    return 0;
}