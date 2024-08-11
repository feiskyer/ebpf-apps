#ifndef __HTTPS_TRACE_H
#define __HTTPS_TRACE_H

#define COMM_LEN 32
#define MAX_BUF_LENGTH 8192

struct event_t {
	__u32 pid;
	__u32 uid;
	__u8 buf[MAX_BUF_LENGTH];
	char comm[COMM_LEN];
	__u32 len;
	__u8 rw;		// 0: read, 1: write
};

#endif				/* __HTTPS_TRACE_H */
