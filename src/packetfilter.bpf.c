// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define MAX_ENTRIES 1024  // Maximum number of tracked IPs

// Cấu trúc key cho LPM Trie map
// ip: Địa chỉ IP của subnet (network byte order)
// prefixlen: Độ dài tiền tố (ví dụ: 24 cho /24)
struct bpf_trie_key {
    __u32 prefixlen;
    __u32 ip; // IPv4 address (network byte order)
};

// Structure for packet statistics by IP
struct packet_stats {
    __u64 dropped;  // Number of dropped packets
    __u64 passed;   // Number of passed packets
};

// Định ]blacklist subnet
// Key: bpf_trie_key (chứa subnet và prefixlen)
// Value: Một giá trị placeholder (u8), sự tồn tại của key đã đủ
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024); // Số lượng subnet tối đa
    __type(key, struct bpf_trie_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC); // Không cấp phát trước, tiết kiệm bộ nhớ
} blacklist_subnets_map SEC(".maps"); // Đổi tên map để rõ ràng hơn

// Map này dùng để nhận tín hiệu từ user-space khi blacklist được cập nhật
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64); // Sử dụng timestamp hoặc counter để báo hiệu cập nhật
} update_signal_map SEC(".maps");

// New map for tracking packet statistics per IP address
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES); // Maximum number of tracked IPs
    __type(key, __u32);               // IP address as key
    __type(value, struct packet_stats); // Statistics as value
} ip_stats_map SEC(".maps");

// Map for global counters (for quick access to totals)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);  // 0: dropped, 1: passed
    __type(key, __u32);
    __type(value, __u64);
} global_stats_map SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Kiểm tra tín hiệu cập nhật từ user-space
    __u32 update_key = 0;
    __u64 *last_update_ts = bpf_map_lookup_elem(&update_signal_map, &update_key);
    if (last_update_ts) {
        bpf_printk("XDP: IP blacklist was updated from user-space.\n");
    }

    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(*eth);

    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    __u32 src_ip = ip->saddr; // IP nguồn của gói tin (network byte order)

    // Tạo key để tra cứu trong LPM Trie
    struct bpf_trie_key key = {
        .prefixlen = 32, // Khi tìm một IP cụ thể trong subnet map, dùng prefixlen 32
        .ip = src_ip
    };

    // Get or initialize packet stats for this IP
    struct packet_stats new_stats = {0};
    struct packet_stats *ip_stats = bpf_map_lookup_elem(&ip_stats_map, &src_ip);
    if (!ip_stats) {
        // If this IP isn't in the map yet, initialize it with zeros
        bpf_map_update_elem(&ip_stats_map, &src_ip, &new_stats, BPF_ANY);
        ip_stats = bpf_map_lookup_elem(&ip_stats_map, &src_ip);
        if (!ip_stats) {
            // This should not happen, but just in case
            goto process_packet;
        }
    }

process_packet:
    // Kiểm tra xem IP nguồn có nằm trong bất kỳ subnet bị blacklist nào không
    // bpf_map_lookup_elem với LPM_TRIE sẽ tìm kiếm tiền tố dài nhất khớp
    if (bpf_map_lookup_elem(&blacklist_subnets_map, &key)) {
        bpf_printk("XDP: Dropping packet from blacklisted IP/subnet: %pI4\n", &src_ip);
        
        // Update IP-specific statistics
        if (ip_stats) {
            __sync_fetch_and_add(&ip_stats->dropped, 1);
        }
        
        // Update global dropped counter
        __u32 dropped_key = 0;
        __u64 *dropped_count = bpf_map_lookup_elem(&global_stats_map, &dropped_key);
        if (dropped_count) {
            __sync_fetch_and_add(dropped_count, 1);
        }
        
        return XDP_DROP; // Chặn gói tin
    }

    // Update IP-specific passed statistics
    if (ip_stats) {
        __sync_fetch_and_add(&ip_stats->passed, 1);
    }
    
    // Update global passed counter
    __u32 passed_key = 1;
    __u64 *passed_count = bpf_map_lookup_elem(&global_stats_map, &passed_key);
    if (passed_count) {
        __sync_fetch_and_add(passed_count, 1);
    }

    return XDP_PASS; // Cho qua
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";