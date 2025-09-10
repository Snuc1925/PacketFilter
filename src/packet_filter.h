// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#ifndef PACKET_FILTER_H
#define PACKET_FILTER_H

#include <cstdint>
#include <string>

namespace packet_filter {
    // Define the key structure for the LPM Trie map
    struct BpfTrieKey {
        __u32 prefixlen;
        __u32 ip; // IPv4 address (network byte order)
    };

    // Structure to track subnet nodes in a linked list
    class SubnetNode {
    public:
        BpfTrieKey key;
        SubnetNode* next;
        
        SubnetNode() : next(nullptr) {}
        ~SubnetNode() = default;
    };

    // Rate limit configuration structure
    struct RateLimit {
        __u32 ip;              // IP address
        __u32 pps;             // Packets per second limit
        __u64 interval_ns;     // Calculated interval in nanoseconds
        
        RateLimit() : ip(0), pps(0), interval_ns(0) {}
        RateLimit(__u32 ip, __u32 pps) : ip(ip), pps(pps) {
            // Calculate interval in nanoseconds
            interval_ns = pps > 0 ? 1000000000ULL / pps : 0;
        }
    };

    // Structure to track rate limits in a linked list
    class RateLimitNode {
    public:
        RateLimit config;
        RateLimitNode* next;
        
        RateLimitNode() : next(nullptr) {}
        explicit RateLimitNode(const RateLimit& cfg) : config(cfg), next(nullptr) {}
        ~RateLimitNode() = default;
    };

    // Function to free a linked list of subnets
    void free_subnet_list(SubnetNode *head);

    // Function to free a linked list of rate limits
    void free_rate_limit_list(RateLimitNode *head);

    // Function to add a subnet to the blacklist map
    int add_to_blacklist(int map_fd, const std::string& subnet_str);

    // Function to add a rate limit to the rate limit map
    int add_to_rate_limits(int map_fd, const RateLimit& limit);

    // Function to remove a subnet from the blacklist map
    int remove_from_blacklist(int map_fd, BpfTrieKey *key);

    // Function to remove a rate limit from the rate limit map
    int remove_from_rate_limits(int map_fd, __u32 ip);

    // Function to read and update blacklist from config file
    int update_from_config();

    // Initialize the packet filter module
    void init(int blacklist_map_fd, int signal_map_fd, int rate_limits_map_fd,
            const std::string& config_file_path, std::string& interface_name,
            uint32_t& ifindex, SubnetNode** subnets, RateLimitNode** rate_limits);
} // namespace packet_filter

#endif /* PACKET_FILTER_H */