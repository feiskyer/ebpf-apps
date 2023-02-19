// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Windows.h needs to be the first include to prevent failures in subsequent headers.
#include <windows.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ebpf_api.h>
#include <io.h>
#include <iostream>
#include <string>
#include <condition_variable>
#include <mutex>

#pragma comment(lib, "ebpfapi.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "ws2_32.lib")


bool _shutdown = false;
std::condition_variable _wait_for_shutdown;
std::mutex _wait_for_shutdown_mutex;

int control_handler(unsigned long control_type)
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
    struct bpf_object* object = bpf_object__open("drop.o");
    if (!object) {
        std::cerr << "bpf_object__open for drop.o failed: " << errno << std::endl;
        return 1;
    }

    if (bpf_object__load(object) < 0) {
        std::cerr << "bpf_object__load for drop.o failed: " << errno << std::endl;
        return 1;
    }

    // Attach program to xdp attach point.
    auto program = bpf_object__find_program_by_name(object, "DropPacket");
    if (!program) {
        std::cerr << "bpf_object__find_program_by_name for \"DropPacket\" failed: " << errno << std::endl;
        return 1;
    }

    auto link = bpf_program__attach(program);
    if (!link) {
        std::cerr << "BPF program conn_track.sys failed to attach: " << errno << std::endl;
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

    // Free the BPF object.
    bpf_object__close(object);
    return 0;
}
