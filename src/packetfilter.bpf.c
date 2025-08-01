// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_BLACKLIST_ENTRIES 1024
#define ETH_P_IP 0x0800

// Định nghĩa map để lưu trữ blacklist
// Key: Địa chỉ IPv4
// Value: Chỉ là một giá trị placeholder (u8), sự tồn tại của key đã đủ
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLACKLIST_ENTRIES);
    __type(key, __u32); // IPv4 address
    __type(value, __u8);
} blacklist_map SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;

    // Kiểm tra xem gói tin có đủ lớn để chứa Ethernet header không
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS; // Không đủ dữ liệu, cho qua
    }

    // Chỉ xử lý gói tin IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(*eth);

    // Kiểm tra xem gói tin có đủ lớn để chứa IP header không
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    // Lấy địa chỉ IP nguồn
    __u32 src_ip = ip->saddr;

    // bpf_printk("Source IP: %pI4\n", &src_ip);    

    // Kiểm tra xem IP nguồn có trong blacklist không
    if (bpf_map_lookup_elem(&blacklist_map, &src_ip)) {
        bpf_printk("XDP: Dropping packet from blacklisted IP: %pI4\n", &src_ip);
        return XDP_DROP; // Chặn gói tin
    }

    return XDP_PASS; // Cho qua
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";