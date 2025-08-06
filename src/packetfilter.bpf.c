// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Include our detector header
#include "l7_ddos_detector.h"

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

#define TCP_PROTOCOL 6
#define UDP_PROTOCOL 17

#define HTTP_PORT 80
#define HTTPS_PORT 443

// Cấu trúc key cho LPM Trie map
struct bpf_trie_key {
    __u32 prefixlen;
    __u32 ip; // IPv4 address (network byte order)
};

// Định nghĩa map để lưu trữ blacklist subnet
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024); 
    __type(key, struct bpf_trie_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC); 
} blacklist_subnets_map SEC(".maps");

// Basic IP stats for packet rate monitoring
struct ip_stats {
    __u64 last_seen_ns; 
    __u32 pkt_count;    
};

// LRU hash map to track packet rates by source IP
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32); 
    __type(value, struct ip_stats);
} ip_rate_map SEC(".maps");

// Connection tracking map (TCP/UDP sessions)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536); 
    __type(key, struct conn_key);
    __type(value, struct conn_info);
} conn_track_map SEC(".maps");

// Map for destination statistics
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096); 
    __type(key, __u32); 
    __type(value, struct dest_stats);
} dest_stats_map SEC(".maps");

// Ring buffer for reporting DDoS events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); 
} ddos_events SEC(".maps");

// Configuration map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct l7_config);
} l7_config_map SEC(".maps");

// Map to track detected potential attackers
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32); 
    __type(value, __u32); 
} potential_attackers_map SEC(".maps");

// Map for update signals
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64); 
} update_signal_map SEC(".maps");

// Default thresholds
const volatile __u64 TIME_WINDOW_NS = 1 * 1000000000ULL; 
const volatile __u32 PACKET_RATE_THRESHOLD = 1000; 
const volatile __u32 REQ_RATE_THRESHOLD = 100;   
const volatile __u32 LATENCY_THRESHOLD_MS = 500; 
const volatile __u32 CONN_RATE_THRESHOLD = 50;   

// Check if an IP is in the blacklist
static __always_inline bool is_ip_blacklisted(__u32 ip) {
    struct bpf_trie_key key = {
        .prefixlen = 32,
        .ip = ip
    };
    return bpf_map_lookup_elem(&blacklist_subnets_map, &key) != NULL;
}

// Update destination statistics based on new packet/request data
static __always_inline void update_dest_stats(struct conn_key *key, struct conn_info *conn, __u64 current_time, bool is_request) {
    struct dest_stats *stats = bpf_map_lookup_elem(&dest_stats_map, &key->dst_ip);
    
    // Get configuration
    __u32 config_key = 0;
    struct l7_config *config = bpf_map_lookup_elem(&l7_config_map, &config_key);
    __u64 window_size = config ? config->window_size_ns : TIME_WINDOW_NS;
    
    if (stats) {
        // Reset counters if window has passed
        if (current_time - stats->window_start_ns > window_size) {
            stats->window_start_ns = current_time;
            stats->request_count = 0;
            stats->connection_count = 0;
            stats->error_count = 0;
        }
        
        // Update stats
        stats->last_updated_ns = current_time;
        
        if (is_request) {
            stats->request_count++;
        } else if (conn->status_code >= 400) {
            stats->error_count++;
        }
        
        // Calculate latency for responses
        if (!is_request && conn->start_time_ns > 0) {
            __u32 latency_ms = (__u32)((current_time - conn->start_time_ns) / 1000000);
            
            // Update max latency
            if (latency_ms > stats->max_latency_ms) {
                stats->max_latency_ms = latency_ms;
            }
            
            // Update average latency (simple moving average)
            if (stats->avg_latency_ms == 0) {
                stats->avg_latency_ms = latency_ms;
            } else {
                stats->avg_latency_ms = (stats->avg_latency_ms * 3 + latency_ms) / 4; // Weighted average
            }
        }
        
        // Calculate DDoS score based on various factors
        __u32 req_threshold = config ? config->req_rate_threshold : REQ_RATE_THRESHOLD;
        __u32 latency_threshold = config ? config->latency_threshold_ms : LATENCY_THRESHOLD_MS;
        __u32 conn_threshold = config ? config->conn_rate_threshold : CONN_RATE_THRESHOLD;
        
        __u32 score = 0;
        __u32 reason = 0;
        
        // Request rate factor
        if (stats->request_count > req_threshold) {
            score += stats->request_count * 100 / req_threshold;
            reason |= DDOS_REASON_REQ_RATE;
        }
        
        // Latency factor
        if (stats->avg_latency_ms > latency_threshold) {
            score += stats->avg_latency_ms * 100 / latency_threshold;
            reason |= DDOS_REASON_LATENCY;
        }
        
        // Connection rate factor
        if (stats->connection_count > conn_threshold) {
            score += stats->connection_count * 100 / conn_threshold;
            reason |= DDOS_REASON_CONN_RATE;
        }
        
        // Update score and reason
        stats->ddos_score = score;
        stats->blacklist_reason = reason;
        
        // Report potential DDoS if score is high
        if (config && config->auto_blacklist && score > config->ddos_score_threshold) {
            // Mark attacker in potential_attackers_map
            bpf_map_update_elem(&potential_attackers_map, &key->src_ip, &reason, BPF_ANY);
            
            // Send event to ringbuffer for userspace processing
            struct ddos_event *event = bpf_ringbuf_reserve(&ddos_events, sizeof(*event), 0);
            if (event) {
                event->dst_ip = key->dst_ip;
                event->src_ip = key->src_ip;
                // event->request_count = stats->request_count;
                event->avg_latency_ms = stats->avg_latency_ms;
                event->blacklist_reason = reason;
                event->protocol = conn->l7_proto;
                event->timestamp = current_time;
                bpf_ringbuf_submit(event, 0);
            }
        }
    } else {
        // Create new stats entry
        struct dest_stats new_stats = {
            .last_updated_ns = current_time,
            .window_start_ns = current_time,
            .request_count = is_request ? 1 : 0,
            .connection_count = 1,
            .error_count = (!is_request && conn->status_code >= 400) ? 1 : 0,
            .avg_latency_ms = 0,
            .max_latency_ms = 0,
            .ddos_score = 0,
            .blacklist_reason = 0
        };
        bpf_map_update_elem(&dest_stats_map, &key->dst_ip, &new_stats, BPF_ANY);
    }
}

// Simplified TCP processing that should pass the verifier
static __always_inline int process_tcp(struct xdp_md *ctx, 
                                      struct ethhdr *eth, 
                                      struct iphdr *ip, 
                                      void *data, void *data_end,
                                      __u64 current_time) {
    // Basic bounds check for TCP header
    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end) {
        return XDP_PASS;
    }
    
    // Extract ports (this should be safe since we checked tcp+1 above)
    __u16 dst_port = bpf_ntohs(tcp->dest);
    __u16 src_port = bpf_ntohs(tcp->source);
    
    // Create connection key
    struct conn_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .src_port = tcp->source,
        .dst_port = tcp->dest,
        .protocol = TCP_PROTOCOL
    };
    
    // Look up connection in our tracking map
    struct conn_info *conn = bpf_map_lookup_elem(&conn_track_map, &key);
    bool new_connection = false;
    bool is_request = false;
    
    // If not found, create a new connection entry
    if (!conn) {
        struct conn_info new_conn = {
            .start_time_ns = current_time,
            .last_seen_ns = current_time,
            .request_count = 0,
            .l7_proto = L7_PROTO_OTHER,
            .req_method = 0,
            .bytes_sent = 0,
            .bytes_received = 0,
            .status_code = 0,
            .state = 0,
            .is_ssl = (dst_port == HTTPS_PORT) ? 1 : 0
        };
        
        // Auto-detect protocol for common ports
        if (dst_port == HTTP_PORT) {
            new_conn.l7_proto = L7_PROTO_HTTP;
        } else if (dst_port == HTTPS_PORT) {
            new_conn.l7_proto = L7_PROTO_HTTPS;
        }
        
        bpf_map_update_elem(&conn_track_map, &key, &new_conn, BPF_ANY);
        conn = bpf_map_lookup_elem(&conn_track_map, &key);
        if (!conn) {
            return XDP_PASS; // Failed to create connection tracking
        }
        new_connection = true;
        
        // For HTTP/HTTPS requests, assume this is a request based on port
        if (dst_port == HTTP_PORT || dst_port == HTTPS_PORT) {
            is_request = true;
            conn->request_count++;
        }
        
        // Increment connection count for the destination
        struct dest_stats *stats = bpf_map_lookup_elem(&dest_stats_map, &key.dst_ip);
        if (stats) {
            stats->connection_count++;
        }
    } else {
        // Update existing connection
        conn->last_seen_ns = current_time;
        
        // Simplification: assume client-to-server packet is a request
        if (dst_port == HTTP_PORT || dst_port == HTTPS_PORT) {
            // This could be a simplified heuristic without deep packet inspection
            if (src_port > 1024 && dst_port < 1024) {
                is_request = true;
                conn->request_count++;
            }
        }
    }
    
    // Update destination statistics
    update_dest_stats(&key, conn, current_time, is_request);
    
    return XDP_PASS;
}

// Main XDP program
SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Verify Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS; // Not IPv4
    }

    // Verify IP header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    __u32 src_ip = ip->saddr; // Source IP (network byte order)
    __u64 current_time = bpf_ktime_get_ns();
    
    // Check signal for blacklist updates
    __u32 update_key = 0;
    __u64 *last_update_ts = bpf_map_lookup_elem(&update_signal_map, &update_key);
    if (last_update_ts) {
        bpf_printk("XDP: IP blacklist was updated from user-space.\n");
    }
    
    // Check if source IP is already blacklisted
    if (is_ip_blacklisted(src_ip)) {
        bpf_printk("XDP: Dropping packet from blacklisted IP/subnet: %pI4\n", &src_ip);
        return XDP_DROP;
    }
    
    // Check if this source IP is a potential attacker
    __u32 *reason = bpf_map_lookup_elem(&potential_attackers_map, &src_ip);
    if (reason && *reason) {
        // Auto-blacklist if configured
        __u32 config_key = 0;
        struct l7_config *config = bpf_map_lookup_elem(&l7_config_map, &config_key);
        if (config && config->auto_blacklist) {
            struct bpf_trie_key key = {
                .prefixlen = 32,
                .ip = src_ip
            };
            __u8 value = 1;
            bpf_map_update_elem(&blacklist_subnets_map, &key, &value, BPF_ANY);
            bpf_printk("XDP: Auto-blacklisted attacker IP: %pI4, reason: %u\n", &src_ip, *reason);
            return XDP_DROP;
        }
    }
    
    // Basic packet rate checking
    struct ip_stats *stats = bpf_map_lookup_elem(&ip_rate_map, &src_ip);
    if (stats) {
        if (current_time - stats->last_seen_ns > TIME_WINDOW_NS) {
            stats->pkt_count = 1;
        } else {
            stats->pkt_count++;
        }
        stats->last_seen_ns = current_time;
        
        // Check if packet rate exceeds threshold
        if (stats->pkt_count > PACKET_RATE_THRESHOLD) {
            __u32 reason = DDOS_REASON_REQ_RATE;
            bpf_map_update_elem(&potential_attackers_map, &src_ip, &reason, BPF_ANY);
            
            struct ddos_event *event = bpf_ringbuf_reserve(&ddos_events, sizeof(*event), 0);
            if (event) {
                event->dst_ip = 0; // Not targeting specific destination
                event->src_ip = src_ip;
                event->request_rate = stats->pkt_count;
                event->avg_latency_ms = 0;
                event->blacklist_reason = reason;
                event->protocol = 0;
                event->timestamp = current_time;
                bpf_ringbuf_submit(event, 0);
            }
        }
    } else {
        // New IP, create entry
        struct ip_stats new_stats = { .last_seen_ns = current_time, .pkt_count = 1 };
        bpf_map_update_elem(&ip_rate_map, &src_ip, &new_stats, BPF_ANY);
    }
    
    // Process Layer 4 protocols for L7 DDoS detection
    if (ip->protocol == TCP_PROTOCOL) {
        return process_tcp(ctx, eth, ip, data, data_end, current_time);
    }

    return XDP_PASS; // Allow packet by default
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";