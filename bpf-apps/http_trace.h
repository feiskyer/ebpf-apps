#ifndef __HTTP_TRACE_H
#define __HTTP_TRACE_H

#define MAX_LENGTH 100

struct event_t {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u32 payload_length;
	__u8 payload[MAX_LENGTH];
};

#endif				/* __HTTP_TRACE_H */
