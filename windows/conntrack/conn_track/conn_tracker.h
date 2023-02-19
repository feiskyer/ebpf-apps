// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include "net/ip.h"

typedef struct _ip_address
{
    union
    {
        uint32_t ipv4;
        ipv6_address_t ipv6;
    };
} ip_address_t;

typedef struct _connection_tuple
{
    ip_address_t src_ip;
    uint16_t src_port;
    ip_address_t dst_ip;
    uint16_t dst_port;
    uint32_t protocol;
    uint32_t compartment_id;
    uint64_t interface_luid;
} connection_tuple_t;

typedef struct _connection_history
{
    connection_tuple_t tuple;
    bool is_ipv4;
    uint64_t start_time;
    uint64_t end_time;
} connection_history_t;
