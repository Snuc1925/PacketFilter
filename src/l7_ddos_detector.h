// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#ifndef L7_DDOS_DETECTOR_H
#define L7_DDOS_DETECTOR_H

// Common structures used by both kernel and user-space programs

// For BPF programs, we should use the types from vmlinux.h
// For userspace, we include stdint.h
#ifdef __BPF__
// BPF program - types already defined in vmlinux.h
#else
// User space program
#include <linux/types.h> 
#endif

// HTTP methods to track
#define HTTP_METHOD_GET     1
#define HTTP_METHOD_POST    2
#define HTTP_METHOD_HEAD    3
#define HTTP_METHOD_PUT     4
#define HTTP_METHOD_DELETE  5
#define HTTP_METHOD_OPTIONS 6
#define HTTP_METHOD_OTHER   7

// Protocol types to track
#define L7_PROTO_HTTP       1
#define L7_PROTO_HTTPS      2
#define L7_PROTO_OTHER      3

// DDoS detection reason flags
#define DDOS_REASON_REQ_RATE       (1 << 0)  // Too many requests per second
#define DDOS_REASON_LATENCY        (1 << 1)  // High latency responses
#define DDOS_REASON_ERROR_RATE     (1 << 2)  // High rate of error responses
#define DDOS_REASON_CONN_RATE      (1 << 3)  // High connection rate
#define DDOS_REASON_INCOMPLETE     (1 << 4)  // High rate of incomplete requests
#define DDOS_REASON_MANUAL         (1 << 7)  // Manually detected

// Connection tracking key (source IP, source port, destination IP, destination port)
struct conn_key {
    __u32 src_ip;    // Source IP (network byte order)
    __u32 dst_ip;    // Destination IP (network byte order)
    __u16 src_port;  // Source port (network byte order)
    __u16 dst_port;  // Destination port (network byte order)
    __u32 protocol;  // L4 protocol (TCP/UDP)
};

// Connection tracking info
struct conn_info {
    __u64 start_time_ns;    // Connection start time
    __u64 last_seen_ns;     // Last packet time
    __u32 request_count;    // Number of requests in this connection
    __u16 l7_proto;         // L7 protocol (HTTP, HTTPS, etc.)
    __u16 req_method;       // HTTP method if applicable
    __u32 bytes_sent;       // Bytes sent from client to server
    __u32 bytes_received;   // Bytes received from server to client
    __u16 status_code;      // HTTP status code if applicable
    __u8  state;            // Connection state
    __u8  is_ssl;           // Is SSL/TLS connection
};

// Per-destination stats
struct dest_stats {
    __u64 last_updated_ns;     // Last update time
    __u64 window_start_ns;     // Start time of current window
    __u32 request_count;       // Number of requests in current window
    __u32 error_count;         // Number of error responses
    __u32 connection_count;    // Number of new connections
    __u32 avg_latency_ms;      // Average latency in ms
    __u32 max_latency_ms;      // Maximum latency in ms
    __u32 ddos_score;          // DDoS score (higher = more likely)
    __u32 blacklist_reason;    // Reason for blacklisting
};

// User configuration (adjustable thresholds)
struct l7_config {
    __u32 req_rate_threshold;      // Max requests per second per destination
    __u32 latency_threshold_ms;    // Latency threshold in ms
    __u32 error_rate_threshold;    // Error rate threshold (percentage * 100)
    __u32 conn_rate_threshold;     // New connections per second threshold
    __u32 window_size_ns;          // Time window for detection in nanoseconds
    __u32 auto_blacklist;          // Auto-blacklist when threshold exceeded (1=on, 0=off)
    __u32 ddos_score_threshold;    // Score threshold for auto-blacklist
    __u32 _padding;                // For 8-byte alignment
};

// For reporting DDoS events to user-space
struct ddos_event {
    __u32 dst_ip;                  // Target IP of the DDoS
    __u32 src_ip;                  // Source IP (attacker)
    __u32 request_rate;            // Requests per second
    __u32 avg_latency_ms;          // Average latency
    __u32 blacklist_reason;        // Reason for detection/blacklisting
    __u32 protocol;                // L7 protocol
    __u64 timestamp;               // Event time
};

#endif /* L7_DDOS_DETECTOR_H */