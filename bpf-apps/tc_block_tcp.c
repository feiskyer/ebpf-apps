#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char **argv)
{
	if (system("tc qdisc add dev eth0 clsact")) {
		perror("tc qdisc add failed");
		exit(1);
	}

	if (system
	    ("tc filter add dev eth0 egress bpf da obj tc_block_tcp.bpf.o sec action/egress"))
	{
		perror("tc qdisc add failed");
		goto cleanup;
	}

	printf("Tracing /sys/kernel/debug/tracing/trace_pipe...\n");
	system("cat /sys/kernel/debug/tracing/trace_pipe");

 cleanup:
	return system("tc qdisc del dev eth0 clsact");
}
