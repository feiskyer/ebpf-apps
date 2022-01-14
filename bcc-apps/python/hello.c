// This is a Hello World example of BPF.
int hello_world(void *ctx)
{
	bpf_trace_printk("Hello, World!");
	return 0;
}
