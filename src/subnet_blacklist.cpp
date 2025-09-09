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

#include "subnet_blacklist.h"

namespace subnet_blacklist {
    // Static variables to maintain state across function calls
    namespace {
        int map_fd_blacklist_subnets; // File descriptor của blacklist map
        int map_fd_update_signal;     // File descriptor của update signal map
        std::string* config_file_path_abs_ptr; // Pointer to đường dẫn tuyệt đối tới file config
        std::string* filter_interface_name_ptr; // Pointer to tên interface
        uint32_t* current_ifindex_ptr; // Pointer to ifindex của interface
        SubnetNode** current_blacklist_subnets_ptr; // Pointer to linked list of current subnets
    }

    void init(int blacklist_map_fd, int signal_map_fd, 
            const std::string& config_file_path, std::string& interface_name,
            uint32_t& ifindex, SubnetNode** subnets) {
        map_fd_blacklist_subnets = blacklist_map_fd;
        map_fd_update_signal = signal_map_fd;
        config_file_path_abs_ptr = &const_cast<std::string&>(config_file_path);
        filter_interface_name_ptr = &interface_name;
        current_ifindex_ptr = &ifindex;
        current_blacklist_subnets_ptr = subnets;
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

    // Hàm đọc và cập nhật blacklist từ file config
    int update_from_config() {
        // Get references to the actual variables via pointers
        std::string& config_file_path_abs = *config_file_path_abs_ptr;
        std::string* filter_interface_name = filter_interface_name_ptr;
        uint32_t* current_ifindex = current_ifindex_ptr;
        SubnetNode** current_blacklist_subnets = current_blacklist_subnets_ptr;
        
        std::ifstream file(config_file_path_abs);
        if (!file.is_open()) {
            std::cerr << "Failed to open config file: " << strerror(errno) << std::endl;
            return -1;
        }

        std::string line;
        std::string iface_name_buf;
        std::string subnet_list_buf;

        bool iface_found = false;
        bool subnet_list_found = false;

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
            }
        }
        file.close();

        if (!iface_found || !subnet_list_found) {
            std::cerr << "Error: Config file must contain 'interface=' and 'ip_blacklist='." << std::endl;
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

        int ip_count = 0;
        SubnetNode* new_subnets_list = nullptr;
        SubnetNode* new_subnets_tail = nullptr;

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

        std::cout << "Total IP entries parsed: " << ip_count << std::endl;

        // --- Bắt đầu quá trình đồng bộ hóa blacklist ---

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

        // 4. Gửi tín hiệu cập nhật đến kernel (cho kernel biết blacklist đã thay đổi)
        __u32 key = 0;
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        __u64 timestamp = static_cast<__u64>(ts.tv_sec) * 1000000000ULL + ts.tv_nsec;

        if (bpf_map_update_elem(map_fd_update_signal, &key, &timestamp, BPF_ANY) != 0) {
            std::cerr << "Failed to signal update to kernel via update_signal_map: " << strerror(errno) << std::endl;
        } else {
            std::cout << "Sent update signal to kernel." << std::endl;
            std::cout << "\n--- IP Subnet Blacklist has been updated! ---\n";
        }

        return 0;
    }

} // namespace subnet_blacklist