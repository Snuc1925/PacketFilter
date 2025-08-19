// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#ifndef SUBNET_BLACKLIST_H
#define SUBNET_BLACKLIST_H

#include <stdint.h>

// Define the key structure for the LPM Trie map
struct bpf_trie_key {
    __u32 prefixlen;
    __u32 ip; // IPv4 address (network byte order)
};

// Structure to track subnet nodes in a linked list
struct subnet_node {
    struct bpf_trie_key key;
    struct subnet_node *next;
};

// Function to free a linked list of subnets
void free_subnet_list(struct subnet_node *head);

// Function to add a subnet to the blacklist map
int add_to_blacklist(int map_fd, const char *subnet_str);

// Function to remove a subnet from the blacklist map
int remove_from_blacklist(int map_fd, struct bpf_trie_key *key);

// Function to read and update blacklist from config file
int update_blacklist_from_config(void);

// Initialize the subnet blacklist module
void subnet_blacklist_init(int blacklist_map_fd, int signal_map_fd, char **config_file_path, char **interface_name, uint32_t *ifindex, struct subnet_node **subnets);

#endif /* SUBNET_BLACKLIST_H */