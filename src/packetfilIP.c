// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_BLACKLIST_ENTRIES 1024
#define ETH_P_IP 0x0800

// Định nghĩa map để lưu trữ blacklist
// Key: Địa chỉ IPv4 (network byte order)
// Value: Chỉ là một giá trị placeholder (u8), sự tồn tại của key đã đủ
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLACKLIST_ENTRIES);
    __type(key, __u32); // IPv4 address
    __type(value, __u8);
} blacklist_map SEC(".maps");

// Map này dùng để nhận tín hiệu từ user-space khi blacklist được cập nhật
// Key: 0 (chỉ có 1 phần tử)
// Value: Một flag hoặc timestamp để báo hiệu cập nhật
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64); // Sử dụng timestamp hoặc counter để báo hiệu cập nhật
} update_signal_map SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Kiểm tra tín hiệu cập nhật từ user-space
    __u32 key = 0;
    __u64 *last_update_ts = bpf_map_lookup_elem(&update_signal_map, &key);
    if (last_update_ts) {
        bpf_printk("XDP: IP blacklist was updated from user-space.\n");
    }


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

    // Lấy địa chỉ IP nguồn (saddr đã ở network byte order, không cần bpf_ntohl)
    __u32 src_ip = ip->saddr;

    // Kiểm tra xem IP nguồn có trong blacklist không
    if (bpf_map_lookup_elem(&blacklist_map, &src_ip)) {
        bpf_printk("XDP: Dropping packet from blacklisted IP: %pI4\n", &src_ip);
        return XDP_DROP; // Chặn gói tin
    }

    return XDP_PASS; // Cho qua
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";