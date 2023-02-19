// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Windows.h needs to be the first include to prevent failures in subsequent headers.
#include <windows.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ebpf_api.h>
#include <io.h>
#include <iostream>
#include <ip2string.h>
#include <Iphlpapi.h>
#include <in6addr.h>
#include <mstcpip.h>
#include <string>
#include <condition_variable>
#include <mutex>
#include <unordered_map>

#include "conn_tracker.h"

#pragma comment(lib, "ebpfapi.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "ws2_32.lib")

std::unordered_map<uint32_t, std::string> _protocol = {{6, "TCP"}, {17, "UDP"}};

std::string interface_luid_to_name(uint64_t luid)
{
    std::string name(IF_MAX_STRING_SIZE + 1, ' ');
    NET_LUID net_luid;
    net_luid.Value = luid;
    if (ConvertInterfaceLuidToNameA(&net_luid, name.data(), name.size()) != 0) {
        name = "unknown";
    }
    name = name.substr(0, name.find_first_of(' '));
    return name;
}


std::string
trim(const std::string& str)
{
    auto start = str.find_first_not_of(' ');
    if (start == std::string::npos)
        return "";
    auto end = str.find_first_of(' ', start);
    if (end == std::string::npos)
        return str.substr(start);
    else {
        return str.substr(start, end - start);
    }
}

#define MAX_IPV4_ADDRESS_LENGTH 16
#define MAX_IPV6_ADDRESS_LENGTH 46

std::string ip_address_to_string(bool ipv4, const ip_address_t& ip_address, uint64_t interface_luid)
{
    std::string buffer;
    if (ipv4) {
        buffer.resize(MAX_IPV4_ADDRESS_LENGTH);
        in_addr addr;
        addr.S_un.S_addr = ip_address.ipv4;
        auto end = RtlIpv4AddressToStringA(&addr, buffer.data());
        buffer.resize(end - buffer.data());
    } else {
        buffer.resize(MAX_IPV6_ADDRESS_LENGTH);
        in_addr6 addr;
        memcpy(addr.u.Byte, ip_address.ipv6, sizeof(ip_address.ipv6));
        auto end = RtlIpv6AddressToStringA(&addr, buffer.data());
        buffer.resize(end - buffer.data());
        
    }
    buffer += "%" + interface_luid_to_name(interface_luid);

    return "[" + trim(buffer) + "]";
}

extern "C"
{
    int
    conn_track_history_callback(void* ctx, void* data, size_t size);
}

int
conn_track_history_callback(void* ctx, void* data, size_t size)
{
    UNREFERENCED_PARAMETER(ctx);

    if (size == sizeof(connection_history_t)) {
        auto history = reinterpret_cast<connection_history_t*>(data);
        auto source = ip_address_to_string(history->is_ipv4, history->tuple.src_ip, history->tuple.interface_luid) + ":" +
                      std::to_string(htons(history->tuple.src_port));
        auto dest = ip_address_to_string(history->is_ipv4, history->tuple.dst_ip, history->tuple.interface_luid) + ":" +
                    std::to_string(htons(history->tuple.dst_port));
        double duration = static_cast<double>(history->end_time);
        duration -= static_cast<double>(history->start_time);
        duration /= 1e9;
        std::cout << source << " -> " << dest << "\t" << _protocol[history->tuple.protocol] << "\t" << duration
                  << std::endl;
    }
    return 0;
}

bool _shutdown = false;
std::condition_variable _wait_for_shutdown;
std::mutex _wait_for_shutdown_mutex;

int
control_handler(unsigned long control_type)
{
    if (control_type != CTRL_C_EVENT) {
        return false;
    }
    std::unique_lock lock(_wait_for_shutdown_mutex);
    _shutdown = true;
    _wait_for_shutdown.notify_all();
    return true;
}

int
main(int argc, char** argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);
    if (!SetConsoleCtrlHandler(control_handler, true)) {
        std::cerr << "SetConsoleCtrlHandler: " << GetLastError() << std::endl;
        return 1;
    }

    std::cerr << "Press Ctrl-C to shutdown" << std::endl;

    // Load eBPF program.
    struct bpf_object* object = bpf_object__open("../conn_ebpf.o");
    if (!object) {
        std::cerr << "bpf_object__open for conn_ebpf.o failed: " << errno << std::endl;
        return 1;
    }

    if (bpf_object__load(object) < 0) {
        std::cerr << "bpf_object__load for conn_ebpf.o failed: " << errno << std::endl;
        return 1;
    }

    // Attach program to sock_ops attach point.
    auto program = bpf_object__find_program_by_name(object, "connection_tracker");
    if (!program) {
        std::cerr << "bpf_object__find_program_by_name for \"connection_tracker\" failed: " << errno << std::endl;
        return 1;
    }

    auto link = bpf_program__attach(program);
    if (!link) {
        std::cerr << "BPF program conn_track.sys failed to attach: " << errno << std::endl;
        return 1;
    }

    // Attach to ring buffer.
    bpf_map* map = bpf_object__find_map_by_name(object, "history_map");
    if (!map) {
        std::cerr << "Unable to locate history map: " << errno << std::endl;
        return 1;
    }
    auto ring = ring_buffer__new(bpf_map__fd(map), conn_track_history_callback, nullptr, nullptr);
    if (!ring) {
        std::cerr << "Unable to create ring buffer: " << errno << std::endl;
        return 1;
    }

    // Wait for Ctrl-C.
    {
        std::unique_lock lock(_wait_for_shutdown_mutex);
        _wait_for_shutdown.wait(lock, []() { return _shutdown; });
    }

    // Detach from the attach point.
    int link_fd = bpf_link__fd(link);
    bpf_link_detach(link_fd);
    bpf_link__destroy(link);

    // Close ring buffer.
    ring_buffer__free(ring);

    // Free the BPF object.
    bpf_object__close(object);
    return 0;
}
