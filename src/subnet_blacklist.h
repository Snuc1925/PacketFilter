// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#ifndef SUBNET_BLACKLIST_H
#define SUBNET_BLACKLIST_H

#include <cstdint>
#include <string>

namespace subnet_blacklist {
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

    // Function to free a linked list of subnets
    void free_subnet_list(SubnetNode *head);

    // Function to add a subnet to the blacklist map
    int add_to_blacklist(int map_fd, const std::string& subnet_str);

    // Function to remove a subnet from the blacklist map
    int remove_from_blacklist(int map_fd, BpfTrieKey *key);

    // Function to read and update blacklist from config file
    int update_from_config();

    // Initialize the subnet blacklist module
    void init(int blacklist_map_fd, int signal_map_fd, 
            const std::string& config_file_path, std::string& interface_name,
            uint32_t& ifindex, SubnetNode** subnets);
} // namespace subnet_blacklist

#endif /* SUBNET_BLACKLIST_H */