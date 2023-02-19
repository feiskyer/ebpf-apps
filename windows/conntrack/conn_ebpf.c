#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <net/ip.h>
#include "conn_track/conn_tracker.h"

inline __attribute__((always_inline)) uint64_t
bpf_ntohll(uint64_t x)
{
    uint64_t upper = bpf_ntohl(x >> 32);
    uint64_t lower = (uint64_t)bpf_ntohl(x & 0xFFFFFFFF) << 32;
    return upper | lower;
}

#define bpf_htonll(x) bpf_ntohll(x)

#ifndef ntohll
#define ntohll bpf_ntohll
#endif
#ifndef htonll
#define htonll bpf_htonll
#endif

// Key is the connection tuple, value is the connection start time.
SEC("maps")
struct bpf_map_def connection_map = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(connection_tuple_t),
    .value_size = sizeof(uint64_t),
    .max_entries = 1024};

// Connection history map containing tuple and connection duration.
SEC("maps")
struct bpf_map_def history_map = {.type = BPF_MAP_TYPE_RINGBUF, .max_entries = 256 * 1024};

__attribute__((always_inline)) void
log_tuple(connection_tuple_t *tuple, bool ipv4, bool connect)
{
    if (ipv4)
    {
        if (connect)
        {
            bpf_printk("Connnection to %x:%d started on if %ld", ntohl(tuple->dst_ip.ipv4), ntohs(tuple->dst_port), tuple->interface_luid);
        }
        else
        {
            bpf_printk("Connnection to %x:%d stopped on if %ld", ntohl(tuple->dst_ip.ipv4), ntohs(tuple->dst_port), tuple->interface_luid);
        }
    }
    else
    {
        uint64_t *ip = (uint64_t *)tuple->dst_ip.ipv6;
        if (connect)
        {
            bpf_printk("Connnection to %llx %llx started on if %ld", ntohll(ip[0]), ntohll(ip[1]), tuple->interface_luid);
        }
        else
        {
            bpf_printk("Connnection to %llx %llx stopped on if %ld", ntohll(ip[0]), ntohll(ip[1]), tuple->interface_luid);
        }
    }
}

__attribute__((always_inline)) void
sock_ops_to_connection_tuple(bpf_sock_ops_t *ctx, bool is_ipv4, connection_tuple_t *tuple)
{
    tuple->compartment_id = ctx->compartment_id;
    tuple->interface_luid = ctx->interface_luid;
    tuple->src_port = ctx->local_port;
    tuple->dst_port = ctx->remote_port;
    tuple->protocol = ctx->protocol;

    if (is_ipv4)
    {
        tuple->src_ip.ipv4 = ctx->local_ip4;
        tuple->dst_ip.ipv4 = ctx->remote_ip4;
    }
    else
    {
        void *ip6 = NULL;
        ip6 = ctx->local_ip6;
        __builtin_memcpy(tuple->src_ip.ipv6, ip6, sizeof(tuple->src_ip.ipv6));
        ip6 = ctx->remote_ip6;
        __builtin_memcpy(tuple->dst_ip.ipv6, ip6, sizeof(tuple->dst_ip.ipv6));
    }
}

__attribute__((always_inline)) void
handle_connection(bpf_sock_ops_t *ctx, bool is_ipv4, bool connected)
{
    connection_tuple_t key = {0};
    sock_ops_to_connection_tuple(ctx, is_ipv4, &key);
    uint64_t now = bpf_ktime_get_ns();

    if (connected)
    {
        log_tuple(&key, is_ipv4, true);
        bpf_map_update_elem(&connection_map, &key, &now, 0);
    }
    else
    {
        uint64_t *start_time = (uint64_t *)bpf_map_lookup_and_delete_elem(&connection_map, &key);
        if (start_time)
        {
            log_tuple(&key, is_ipv4, false);
            connection_history_t history;
            // Memset is required due to padding within this struct.
            __builtin_memset(&history, 0, sizeof(history));
            history.tuple = key;
            history.is_ipv4 = is_ipv4;
            history.start_time = *start_time;
            history.end_time = now;
            bpf_ringbuf_output(&history_map, &history, sizeof(history), 0);
        }
    }
}

SEC("sockops")
int connection_tracker(bpf_sock_ops_t *ctx)
{
    int result = 0;
    bool connected;
    switch (ctx->op)
    {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        connected = true;
        break;
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        connected = true;
        break;
    case BPF_SOCK_OPS_CONNECTION_DELETED_CB:
        connected = false;
        break;
    default:
        result = -1;
    }
    if (result == 0)
        handle_connection(ctx, (ctx->family == AF_INET), connected);

    return 0;
}
