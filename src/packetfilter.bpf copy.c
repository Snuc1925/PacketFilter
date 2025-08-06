// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

// Cấu trúc key cho LPM Trie map
// ip: Địa chỉ IP của subnet (network byte order)
// prefixlen: Độ dài tiền tố (ví dụ: 24 cho /24)
struct bpf_trie_key {
    __u32 prefixlen;
    __u32 ip; // IPv4 address (network byte order)
};

// Định nghĩa map để lưu trữ blacklist subnet
// Key: bpf_trie_key (chứa subnet và prefixlen)
// Value: Một giá trị placeholder (u8), sự tồn tại của key đã đủ
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024); // Số lượng subnet tối đa
    __type(key, struct bpf_trie_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC); // Không cấp phát trước, tiết kiệm bộ nhớ
} blacklist_subnets_map SEC(".maps"); // Đổi tên map để rõ ràng hơn


// ------------------ DDoS ----------------------------
struct ip_stats {
    __u64 last_seen_ns; // Thời gian thấy packet cuối cùng (nanosecond)
    __u32 pkt_count;    // Số packet trong khoảng thời gian
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH); // LRU Hash tự động dọn dẹp các IP ít truy cập
    __uint(max_entries, 10000);
    __type(key, __u32); // IP nguồn
    __type(value, struct ip_stats);
} ip_rate_map SEC(".maps");

const volatile __u64 TIME_WINDOW_NS = 1 * 1000000000ULL; // 1 giây
const volatile __u32 PACKET_RATE_THRESHOLD = 1000; // Ngưỡng: 1000 packet/giây
// ----------------------------------------------------

// Map này dùng để nhận tín hiệu từ user-space khi blacklist được cập nhật
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

    // Kiểm tra xem IP nguồn có nằm trong bất kỳ subnet bị blacklist nào không
    // bpf_map_lookup_elem với LPM_TRIE sẽ tìm kiếm tiền tố dài nhất khớp
    if (bpf_map_lookup_elem(&blacklist_subnets_map, &key)) {
        bpf_printk("XDP: Dropping packet from blacklisted IP/subnet: %pI4\n", &src_ip);
        return XDP_DROP; // Chặn gói tin
    }

    __u64 current_time = bpf_ktime_get_ns();
    struct ip_stats *stats = bpf_map_lookup_elem(&ip_rate_map, &src_ip);

    if (stats) {
        if (current_time - stats->last_seen_ns > TIME_WINDOW_NS) {
            stats->pkt_count = 1;
        } else {
            stats->pkt_count++;
        }
        stats->last_seen_ns = current_time;
    } else {
        // IP mới, tạo entry mới
        struct ip_stats new_stats = { .last_seen_ns = current_time, .pkt_count = 1 };
        bpf_map_update_elem(&ip_rate_map, &src_ip, &new_stats, BPF_ANY);
    }        

    return XDP_PASS; // Cho qua
}





char LICENSE[] SEC("license") = "Dual BSD/GPL";