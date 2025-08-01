// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "packetfilter.skel.h" // File skeleton được tạo tự động

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

// Hàm thêm một IP vào blacklist map
static int add_to_blacklist(int map_fd, const char *ip_str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        fprintf(stderr, "Invalid IP address: %s\n", ip_str);
        return -1;
    }
    __u32 key = addr.s_addr;
    __u8 value = 1;
    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update blacklist map for IP: %s\n", ip_str);
        return -1;
    }
    printf("Added %s to blacklist.\n", ip_str);
    return 0;
}

int main(int argc, char **argv) {
    struct packetfilter_bpf *skel;
    int err;
    int ifindex;
    int map_fd;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <interface> <ip_to_block_1> [ip_to_block_2] ...\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }

    // Mở, tải và xác thực chương trình BPF
    skel = packetfilter_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    struct bpf_link *link = bpf_program__attach_xdp(skel->progs.xdp_filter, ifindex);
    if (!link) {
        fprintf(stderr, "Failed to attach XDP program to ifindex %d\n", ifindex);
        goto cleanup;
    }    

    printf("Successfully loaded and attached BPF program on interface %s\n", ifname);

    // Lấy file descriptor của map
    map_fd = bpf_map__fd(skel->maps.blacklist_map);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get map FD\n");
        err = -1;
        goto cleanup;
    }

    // Thêm các IP từ command-line vào blacklist
    for (int i = 2; i < argc; i++) {
        if (add_to_blacklist(map_fd, argv[i]) != 0) {
            err = -1;
            goto cleanup;
        }
    }

    // Bắt tín hiệu ngắt (Ctrl+C) để dọn dẹp
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("Packet filter is running. Press Ctrl+C to exit.\n");
    printf("Run 'sudo cat /sys/kernel/debug/tracing/trace_pipe' to see dropped packets.\n");

    while (!exiting) {
        sleep(1);
    }

cleanup:
    // Dọn dẹp: gỡ chương trình BPF và giải phóng skeleton
    printf("Detaching BPF program and cleaning up...\n");
    packetfilter_bpf__destroy(skel);
    return -err;
}