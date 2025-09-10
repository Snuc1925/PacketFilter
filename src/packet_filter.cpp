// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <cstring>
#include <arpa/inet.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <cerrno>
#include <ctime>
#include <vector>
#include <sstream>
#include <algorithm>
#include <memory>

#include "packet_filter.h"

namespace packet_filter {
    // Static variables to maintain state across function calls
    namespace {
        int map_fd_blacklist_subnets; // File descriptor của blacklist map
        int map_fd_update_signal;     // File descriptor của update signal map
        int map_fd_rate_limits;       // File descriptor của rate limits map
        std::string* config_file_path_abs_ptr; // Pointer to đường dẫn tuyệt đối tới file config
        std::string* filter_interface_name_ptr; // Pointer to tên interface
        uint32_t* current_ifindex_ptr; // Pointer to ifindex của interface
        SubnetNode** current_blacklist_subnets_ptr; // Pointer to linked list of current subnets
        RateLimitNode** current_rate_limits_ptr;   // Pointer to linked list of current rate limits
    }

    void init(int blacklist_map_fd, int signal_map_fd, int rate_limits_map_fd,
            const std::string& config_file_path, std::string& interface_name,
            uint32_t& ifindex, SubnetNode** subnets, RateLimitNode** rate_limits) {
        map_fd_blacklist_subnets = blacklist_map_fd;
        map_fd_update_signal = signal_map_fd;
        map_fd_rate_limits = rate_limits_map_fd;
        config_file_path_abs_ptr = &const_cast<std::string&>(config_file_path);
        filter_interface_name_ptr = &interface_name;
        current_ifindex_ptr = &ifindex;
        current_blacklist_subnets_ptr = subnets;
        current_rate_limits_ptr = rate_limits;
    }

    void free_subnet_list(SubnetNode *head) {
        SubnetNode *current = head;
        SubnetNode *next;
        while (current != nullptr) {
            next = current->next;
            delete current;
            current = next;
        }
    }

    void free_rate_limit_list(RateLimitNode *head) {
        RateLimitNode *current = head;
        RateLimitNode *next;
        while (current != nullptr) {
            next = current->next;
            delete current;
            current = next;
        }
    }

    // Hàm thêm một subnet vào blacklist map
    // subnet_str ví dụ "192.168.1.0/24"
    int add_to_blacklist(int map_fd, const std::string& subnet_str) {
        struct in_addr addr;
        char ip_str[INET_ADDRSTRLEN];
        int prefixlen;
        
        size_t slash_pos = subnet_str.find('/');
        if (slash_pos != std::string::npos) {
            // Có prefixlen
            std::string ip_part = subnet_str.substr(0, slash_pos);
            strncpy(ip_str, ip_part.c_str(), sizeof(ip_str) - 1);
            ip_str[sizeof(ip_str) - 1] = '\0';
            prefixlen = std::stoi(subnet_str.substr(slash_pos + 1));
        } else {
            // Chỉ là IP đơn lẻ, coi như /32
            strncpy(ip_str, subnet_str.c_str(), sizeof(ip_str) - 1);
            ip_str[sizeof(ip_str) - 1] = '\0';
            prefixlen = 32;
        }

        if (inet_pton(AF_INET, ip_str, &addr) != 1) {
            std::cerr << "Invalid IP address in subnet: " << subnet_str << std::endl;
            return -1;
        }

        if (prefixlen < 0 || prefixlen > 32) {
            std::cerr << "Invalid prefix length: " << prefixlen << " in subnet: " << subnet_str << std::endl;
            return -1;
        }

        BpfTrieKey key = {
            .prefixlen = static_cast<__u32>(prefixlen),
            .ip = addr.s_addr // IP mạng (network byte order)
        };
        __u8 value = 1; // Giá trị placeholder

        if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
            std::cerr << "Failed to update blacklist subnet map: " << strerror(errno) << std::endl;
            return -1;
        }
        return 0;
    }

    // Function to add a rate limit to the rate limit map
    int add_to_rate_limits(int map_fd, const RateLimit& limit) {
        struct in_addr addr;
        addr.s_addr = limit.ip;
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
        
        // Create BPF rate limit structure
        struct {
            __u32 packets_per_second;
            __u64 packet_interval_ns;
        } bpf_rate_limit = {
            .packets_per_second = limit.pps,
            .packet_interval_ns = limit.interval_ns
        };

        if (bpf_map_update_elem(map_fd, &limit.ip, &bpf_rate_limit, BPF_ANY) != 0) {
            std::cerr << "Failed to update rate limits map for IP " << ip_str 
                      << " (" << limit.pps << " pps): " << strerror(errno) << std::endl;
            return -1;
        }
        
        std::cout << "Added rate limit for IP " << ip_str << " at " << limit.pps 
                  << " pps (interval: " << limit.interval_ns << "ns)" << std::endl;
        return 0;
    }

    // Hàm xóa một subnet khỏi blacklist map
    int remove_from_blacklist(int map_fd, BpfTrieKey *key) {
        if (bpf_map_delete_elem(map_fd, key) != 0) {
            if (errno != ENOENT) {
                std::cerr << "Failed to delete from blacklist subnet map: " << strerror(errno) << std::endl;
                return -1;
            }
        }
        struct in_addr addr;
        addr.s_addr = key->ip;
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
        std::cout << "Removed " << ip_str << "/" << key->prefixlen << " from blacklist BPF map." << std::endl;
        return 0;
    }

    // Function to remove a rate limit from the rate limit map
    int remove_from_rate_limits(int map_fd, __u32 ip) {
        if (bpf_map_delete_elem(map_fd, &ip) != 0) {
            if (errno != ENOENT) {
                std::cerr << "Failed to delete from rate limits map: " << strerror(errno) << std::endl;
                return -1;
            }
        }
        struct in_addr addr;
        addr.s_addr = ip;
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
        std::cout << "Removed rate limit for " << ip_str << " from rate limits BPF map." << std::endl;
        return 0;
    }

    // Hàm đọc và cập nhật blacklist từ file config
    int update_from_config() {
        // Get references to the actual variables via pointers
        std::string& config_file_path_abs = *config_file_path_abs_ptr;
        std::string* filter_interface_name = filter_interface_name_ptr;
        uint32_t* current_ifindex = current_ifindex_ptr;
        SubnetNode** current_blacklist_subnets = current_blacklist_subnets_ptr;
        RateLimitNode** current_rate_limits = current_rate_limits_ptr;
        
        std::ifstream file(config_file_path_abs);
        if (!file.is_open()) {
            std::cerr << "Failed to open config file: " << strerror(errno) << std::endl;
            return -1;
        }

        std::string line;
        std::string iface_name_buf;
        std::string subnet_list_buf;
        std::string rate_limits_buf;

        bool iface_found = false;
        bool subnet_list_found = false;
        bool rate_limits_found = false;

        while (std::getline(file, line)) {
            // Skip empty lines and comments
            if (line.empty() || line[0] == '#') {
                continue;
            }

            if (line.find("interface=") == 0) {
                iface_found = true;
                iface_name_buf = line.substr(strlen("interface="));
                std::cout << "Config: Interface name: " << iface_name_buf << std::endl;
            } else if (line.find("ip_blacklist=") == 0) {
                subnet_list_found = true;
                subnet_list_buf = line.substr(strlen("ip_blacklist="));
                // std::cout << "Config: IP blacklist string: " << subnet_list_buf << std::endl;
            } else if (line.find("ip_rate_limits=") == 0) {
                rate_limits_found = true;
                rate_limits_buf = line.substr(strlen("ip_rate_limits="));
                std::cout << "Config: IP rate limits string: " << rate_limits_buf << std::endl;
            }
        }
        file.close();

        if (!iface_found) {
            std::cerr << "Error: Config file must contain 'interface='." << std::endl;
            return -1;
        }

        // So sánh interface name (chỉ được đặt 1 lần lúc khởi động)
        if (filter_interface_name->empty()) { // Lần đầu đọc config
            *filter_interface_name = iface_name_buf;
            *current_ifindex = if_nametoindex(filter_interface_name->c_str());
            if (!*current_ifindex) {
                std::cerr << "if_nametoindex error: " << strerror(errno) << std::endl;
                return -1;
            }
            std::cout << "Initial interface set to " << *filter_interface_name << " (index " << *current_ifindex << ")." << std::endl;
        } else if (*filter_interface_name != iface_name_buf) {
            std::cerr << "Error: Changing interface name (" << *filter_interface_name << " to " 
                    << iface_name_buf << ") dynamically is not supported. Please restart." << std::endl;
            return -1;
        }

        // Process subnet blacklist (if present)
        int ip_count = 0;
        SubnetNode* new_subnets_list = nullptr;
        SubnetNode* new_subnets_tail = nullptr;

        if (subnet_list_found) {
            // Parse the subnet list
            std::stringstream ss(subnet_list_buf);
            std::string subnet;
            
            while (std::getline(ss, subnet, ',')) {
                // Trim whitespace
                subnet.erase(0, subnet.find_first_not_of(" \t"));
                subnet.erase(subnet.find_last_not_of(" \t") + 1);
                
                if (!subnet.empty()) {
                    struct in_addr addr;
                    std::string ip_only;
                    int prefixlen;
                    
                    size_t slash_pos = subnet.find('/');
                    if (slash_pos != std::string::npos) {
                        ip_only = subnet.substr(0, slash_pos);
                        prefixlen = std::stoi(subnet.substr(slash_pos + 1));
                    } else {
                        ip_only = subnet;
                        prefixlen = 32;
                    }

                    if (inet_pton(AF_INET, ip_only.c_str(), &addr) == 1) {
                        if (prefixlen >= 0 && prefixlen <= 32) {
                            auto new_node = new SubnetNode();
                            if (!new_node) {
                                std::cerr << "Failed to allocate subnet_node" << std::endl;
                                free_subnet_list(new_subnets_list);
                                return -1;
                            }
                            new_node->key.ip = addr.s_addr;
                            new_node->key.prefixlen = static_cast<__u32>(prefixlen);
                            new_node->next = nullptr;
                            
                            if (new_subnets_list == nullptr) {
                                new_subnets_list = new_node;
                                new_subnets_tail = new_node;
                            } else {
                                new_subnets_tail->next = new_node;
                                new_subnets_tail = new_node;
                            }
                            ip_count++;
                        } else {
                            std::cerr << "Warning: Invalid prefix length for '" << subnet << "' in config file." << std::endl;
                        }
                    } else {
                        std::cerr << "Warning: Invalid IP address '" << ip_only << "' in config file." << std::endl;
                    }
                }
            }

            std::cout << "Total blacklist IP entries parsed: " << ip_count << std::endl;
        } else {
            std::cout << "No blacklist configured, skipping IP blacklist update." << std::endl;
        }

        // Process rate limits (if present)
        int rate_limit_count = 0;
        RateLimitNode* new_rate_limits_list = nullptr;
        RateLimitNode* new_rate_limits_tail = nullptr;

        if (rate_limits_found) {
            // Parse the rate limits list (format: IP:PPS,IP:PPS,...)
            std::stringstream ss(rate_limits_buf);
            std::string rate_limit_entry;
            
            while (std::getline(ss, rate_limit_entry, ',')) {
                // Trim whitespace
                rate_limit_entry.erase(0, rate_limit_entry.find_first_not_of(" \t"));
                rate_limit_entry.erase(rate_limit_entry.find_last_not_of(" \t") + 1);
                
                if (!rate_limit_entry.empty()) {
                    size_t colon_pos = rate_limit_entry.find(':');
                    if (colon_pos != std::string::npos) {
                        std::string ip_str = rate_limit_entry.substr(0, colon_pos);
                        std::string pps_str = rate_limit_entry.substr(colon_pos + 1);
                        
                        struct in_addr addr;
                        if (inet_pton(AF_INET, ip_str.c_str(), &addr) == 1) {
                            try {
                                __u32 pps = static_cast<__u32>(std::stoul(pps_str));
                                if (pps > 0) {
                                    RateLimit limit(addr.s_addr, pps);
                                    auto new_node = new RateLimitNode(limit);
                                    
                                    if (!new_node) {
                                        std::cerr << "Failed to allocate rate_limit_node" << std::endl;
                                        free_rate_limit_list(new_rate_limits_list);
                                        free_subnet_list(new_subnets_list);
                                        return -1;
                                    }
                                    
                                    if (new_rate_limits_list == nullptr) {
                                        new_rate_limits_list = new_node;
                                        new_rate_limits_tail = new_node;
                                    } else {
                                        new_rate_limits_tail->next = new_node;
                                        new_rate_limits_tail = new_node;
                                    }
                                    rate_limit_count++;
                                } else {
                                    std::cerr << "Warning: PPS must be greater than 0 for '" 
                                              << rate_limit_entry << "' in config file." << std::endl;
                                }
                            } catch (const std::exception& e) {
                                std::cerr << "Warning: Invalid PPS value for '" << rate_limit_entry 
                                          << "' in config file: " << e.what() << std::endl;
                            }
                        } else {
                            std::cerr << "Warning: Invalid IP address in rate limit entry '" 
                                      << rate_limit_entry << "' in config file." << std::endl;
                        }
                    } else {
                        std::cerr << "Warning: Invalid rate limit format (expected IP:PPS) for '" 
                                  << rate_limit_entry << "' in config file." << std::endl;
                    }
                }
            }

            std::cout << "Total rate limit entries parsed: " << rate_limit_count << std::endl;
        } else {
            std::cout << "No rate limits configured, skipping rate limit update." << std::endl;
        }

        // --- Bắt đầu quá trình đồng bộ hóa blacklist ---
        if (subnet_list_found) {
            // 1. Xác định subnets cần xóa (có trong current_blacklist_subnets nhưng không có trong new_subnets_list)
            SubnetNode *current_ptr = *current_blacklist_subnets;
            while (current_ptr != nullptr) {
                bool found = false;
                SubnetNode *new_ptr = new_subnets_list;
                while (new_ptr != nullptr) {
                    if (current_ptr->key.ip == new_ptr->key.ip &&
                        current_ptr->key.prefixlen == new_ptr->key.prefixlen) {
                        found = true;
                        break;
                    }
                    new_ptr = new_ptr->next;
                }
                if (!found) {
                    remove_from_blacklist(map_fd_blacklist_subnets, &current_ptr->key);
                }
                current_ptr = current_ptr->next;
            }

            // 2. Xác định subnets cần thêm (có trong new_subnets_list nhưng không có trong current_blacklist_subnets)
            SubnetNode *new_ptr = new_subnets_list;
            while (new_ptr != nullptr) {
                bool found = false;
                current_ptr = *current_blacklist_subnets;
                while (current_ptr != nullptr) {
                    if (new_ptr->key.ip == current_ptr->key.ip &&
                        new_ptr->key.prefixlen == current_ptr->key.prefixlen) {
                        found = true;
                        break;
                    }
                    current_ptr = current_ptr->next;
                }
                if (!found) {
                    struct in_addr addr;
                    addr.s_addr = new_ptr->key.ip;
                    char subnet_str_buf[INET_ADDRSTRLEN + 4]; // IP + /XX
                    snprintf(subnet_str_buf, sizeof(subnet_str_buf), "%s/%u", inet_ntoa(addr), new_ptr->key.prefixlen);
                    add_to_blacklist(map_fd_blacklist_subnets, subnet_str_buf);
                }
                new_ptr = new_ptr->next;
            }

            // 3. Cập nhật danh sách Subnet hiện tại
            free_subnet_list(*current_blacklist_subnets); // Giải phóng danh sách cũ
            *current_blacklist_subnets = new_subnets_list; // Gán danh sách mới
        }

        // --- Begin rate limits synchronization ---
        if (rate_limits_found) {
            // 1. Identify rate limits to remove (in current list but not in new list)
            RateLimitNode *current_rl_ptr = *current_rate_limits;
            while (current_rl_ptr != nullptr) {
                bool found = false;
                RateLimitNode *new_rl_ptr = new_rate_limits_list;
                while (new_rl_ptr != nullptr) {
                    if (current_rl_ptr->config.ip == new_rl_ptr->config.ip) {
                        found = true;
                        break;
                    }
                    new_rl_ptr = new_rl_ptr->next;
                }
                if (!found) {
                    remove_from_rate_limits(map_fd_rate_limits, current_rl_ptr->config.ip);
                }
                current_rl_ptr = current_rl_ptr->next;
            }

            // 2. Identify rate limits to add or update (in new list but not in current list, or with different PPS)
            RateLimitNode *new_rl_ptr = new_rate_limits_list;
            while (new_rl_ptr != nullptr) {
                bool found = false;
                bool needs_update = true;
                
                current_rl_ptr = *current_rate_limits;
                while (current_rl_ptr != nullptr) {
                    if (new_rl_ptr->config.ip == current_rl_ptr->config.ip) {
                        found = true;
                        // Check if PPS changed
                        if (new_rl_ptr->config.pps == current_rl_ptr->config.pps) {
                            needs_update = false;
                        }
                        break;
                    }
                    current_rl_ptr = current_rl_ptr->next;
                }
                
                if (!found || needs_update) {
                    add_to_rate_limits(map_fd_rate_limits, new_rl_ptr->config);
                }
                
                new_rl_ptr = new_rl_ptr->next;
            }

            // 3. Update the current rate limits list
            free_rate_limit_list(*current_rate_limits); // Free the old list
            *current_rate_limits = new_rate_limits_list; // Assign the new list
        }

        // 4. Gửi tín hiệu cập nhật đến kernel (cho kernel biết blacklist đã thay đổi)
        __u32 key = 0;
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        __u64 timestamp = static_cast<__u64>(ts.tv_sec) * 1000000000ULL + ts.tv_nsec;

        if (bpf_map_update_elem(map_fd_update_signal, &key, &timestamp, BPF_ANY) != 0) {
            std::cerr << "Failed to signal update to kernel via update_signal_map: " << strerror(errno) << std::endl;
        } else {
            std::cout << "Sent update signal to kernel." << std::endl;
            std::cout << "\n--- Packet filter configuration has been updated! ---\n";
        }

        return 0;
    }

} // namespace packet_filter