// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "packetfilter.skel.h" // File skeleton được tạo tự động
#include <cerrno> // For errno
#include <sys/inotify.h> // For inotify
#include <limits.h> // For PATH_MAX
#include <ctime> // For clock_gettime
#include <libgen.h> // For dirname
#include <algorithm> // For std::sort
#include <vector>
#include <string>
#include <memory>
#include <fstream>
#include <iomanip>

// Include the packet filter header
#include "packet_filter.h"

// Define event buffer size for inotify
#define EVENT_SIZE (sizeof(struct inotify_event) + NAME_MAX + 1)
#define BUF_LEN (1024 * EVENT_SIZE)
#define MAX_ENTRIES 1024  // Maximum number of tracked IPs

#define DEFAULT_CONFIG_FILE_RELATIVE "../src/config.txt"

namespace {
    // Structure for packet statistics by IP (must match the BPF struct)
    struct PacketStats {
        __u64 dropped;  // Number of dropped packets
        __u64 passed;   // Number of passed packets
    };

    volatile bool exiting = false;
    int map_fd_blacklist_subnets; // File descriptor của blacklist map (giờ là LPM Trie)
    int map_fd_update_signal;     // File descriptor của update signal map
    int map_fd_ip_stats;          // File descriptor for IP statistics map
    int map_fd_global_stats;      // File descriptor for global statistics map
    int map_fd_rate_limits;       // File descriptor for rate limits map
    int map_fd_ip_timestamps;     // File descriptor for IP timestamps map
    std::string config_file_path_abs; // Đường dẫn tuyệt đối tới file config
    std::string filter_interface_name; // Tên interface
    uint32_t current_ifindex; // ifindex của interface
    packet_filter::SubnetNode* current_blacklist_subnets = nullptr; // Linked list of current subnets
    packet_filter::RateLimitNode* current_rate_limits = nullptr;   // Linked list of current rate limits

    void sig_handler(int sig) {
        exiting = true;
    }

    // Function to print packet statistics when program exits
    void print_statistics() {
        std::cout << "\n-------- Packet Filter Statistics --------\n";
        
        // Print global statistics
        __u32 key = 0;
        __u64 dropped = 0;
        if (bpf_map_lookup_elem(map_fd_global_stats, &key, &dropped) == 0) {
            key = 1;
            __u64 passed = 0;
            if (bpf_map_lookup_elem(map_fd_global_stats, &key, &passed) == 0) {
                std::cout << "Total packets: " << (dropped + passed)
                          << " (Dropped: " << dropped << ", Passed: " << passed << ")\n";
            }
        }
        
        // Collect per-IP statistics
        struct IpEntry {
            __u32 ip;
            PacketStats stats;
        };
        std::vector<IpEntry> entries;

        __u32 ip_key = 0;
        PacketStats stats;

        while (bpf_map_get_next_key(map_fd_ip_stats, entries.empty() ? nullptr : &ip_key, &ip_key) == 0) {
            if (bpf_map_lookup_elem(map_fd_ip_stats, &ip_key, &stats) == 0 &&
                (stats.dropped > 0 || stats.passed > 0)) {
                entries.push_back({ip_key, stats});
            }
        }

        if (entries.empty()) {
            std::cout << "\nNo packet statistics recorded.\n";
            return;
        }

        // Sort by dropped packets (descending)
        std::sort(entries.begin(), entries.end(), 
            [](const IpEntry& a, const IpEntry& b) {
                return a.stats.dropped > b.stats.dropped;
            }
        );

        // Open file for writing
        std::ofstream stats_file("stats.txt");
        if (!stats_file.is_open()) {
            std::cerr << "Error opening stats.txt: " << strerror(errno) << std::endl;
            return;
        }

        // Print and write results
        stats_file << std::left << std::setw(15) << "IP Address" << "  " 
                  << std::right << std::setw(10) << "Dropped" << "  " 
                  << std::setw(10) << "Passed" << "  " 
                  << std::setw(10) << "Total" << std::endl;
        stats_file << "---------------------------------------------------" << std::endl;

        for (const auto& entry : entries) {
            struct in_addr addr;
            addr.s_addr = entry.ip;
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

            stats_file << std::left << std::setw(15) << ip_str << "  " 
                      << std::right << std::setw(10) << entry.stats.dropped << "  " 
                      << std::setw(10) << entry.stats.passed << "  " 
                      << std::setw(10) << (entry.stats.dropped + entry.stats.passed) 
                      << std::endl;
        }

        stats_file.close();
        std::cout << "Per-IP statistics written to stats.txt\n";
    }
}

int main(int argc, char **argv) {
    std::unique_ptr<packetfilter_bpf> skel = nullptr;
    std::unique_ptr<bpf_link, void(*)(bpf_link*)> link(nullptr, [](bpf_link* l) {
        if (l) bpf_link__destroy(l);
    });
    int err = 0;
    int inotify_fd = -1;
    int watch_descriptor = -1;
    char buffer[BUF_LEN];

    // Lấy đường dẫn của executable
    char executable_path_buf[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", executable_path_buf, sizeof(executable_path_buf) - 1);
    if (len == -1) {
        std::cerr << "Error getting executable path: " << strerror(errno) << std::endl;
        return 1;
    }
    executable_path_buf[len] = '\0';

    // Lấy thư mục chứa executable
    std::string executable_path(executable_path_buf);
    char* dir_path = dirname(executable_path_buf);
    if (!dir_path) {
        std::cerr << "Error getting directory name: " << strerror(errno) << std::endl;
        return 1;
    }

    // Tạo đường dẫn tuyệt đối đến file config
    config_file_path_abs = std::string(dir_path) + "/" + DEFAULT_CONFIG_FILE_RELATIVE;
    std::cout << "Using config file: " << config_file_path_abs << std::endl;

    if (argc != 1) {
        std::cerr << "Usage: " << argv[0] << std::endl;
        err = 1;
        goto cleanup_early;
    }

    // Mở, tải và xác thực chương trình BPF
    skel.reset(packetfilter_bpf__open_and_load());
    if (!skel) {
        std::cerr << "Failed to open and load BPF skeleton" << std::endl;
        err = 1;
        goto cleanup_early;
    }

    // Lấy file descriptor của map blacklist_subnets_map
    map_fd_blacklist_subnets = bpf_map__fd(skel->maps.blacklist_subnets_map);
    if (map_fd_blacklist_subnets < 0) {
        std::cerr << "Failed to get blacklist_subnets_map FD" << std::endl;
        err = -1;
        goto cleanup_early;
    }

    // Lấy file descriptor của map update_signal_map
    map_fd_update_signal = bpf_map__fd(skel->maps.update_signal_map);
    if (map_fd_update_signal < 0) {
        std::cerr << "Failed to get update_signal_map FD" << std::endl;
        err = -1;
        goto cleanup_early;
    }
    
    // Get file descriptors for statistics maps
    map_fd_ip_stats = bpf_map__fd(skel->maps.ip_stats_map);
    if (map_fd_ip_stats < 0) {
        std::cerr << "Failed to get ip_stats_map FD" << std::endl;
        err = -1;
        goto cleanup_early;
    }
    
    map_fd_global_stats = bpf_map__fd(skel->maps.global_stats_map);
    if (map_fd_global_stats < 0) {
        std::cerr << "Failed to get global_stats_map FD" << std::endl;
        err = -1;
        goto cleanup_early;
    }
    
    // Get file descriptors for rate limiting maps
    map_fd_rate_limits = bpf_map__fd(skel->maps.ip_rate_limits_map);
    if (map_fd_rate_limits < 0) {
        std::cerr << "Failed to get ip_rate_limits_map FD" << std::endl;
        err = -1;
        goto cleanup_early;
    }
    
    map_fd_ip_timestamps = bpf_map__fd(skel->maps.ip_timestamps_map);
    if (map_fd_ip_timestamps < 0) {
        std::cerr << "Failed to get ip_timestamps_map FD" << std::endl;
        err = -1;
        goto cleanup_early;
    }
    
    // Initialize global counters to zero
    {
        __u32 key = 0;  // dropped counter
        __u64 value = 0;
        if (bpf_map_update_elem(map_fd_global_stats, &key, &value, BPF_ANY) != 0) {
            std::cerr << "Failed to initialize dropped packets counter: " << strerror(errno) << std::endl;
        }
        
        key = 1;  // passed counter
        if (bpf_map_update_elem(map_fd_global_stats, &key, &value, BPF_ANY) != 0) {
            std::cerr << "Failed to initialize passed packets counter: " << strerror(errno) << std::endl;
        }
    }

    // Initialize the packet filter module
    packet_filter::init(map_fd_blacklist_subnets, map_fd_update_signal, map_fd_rate_limits,
                       config_file_path_abs, filter_interface_name, 
                       current_ifindex, &current_blacklist_subnets, &current_rate_limits);

    // Đọc cấu hình lần đầu và attach XDP
    if (packet_filter::update_from_config() != 0) {
        err = -1;
        goto cleanup_early;
    }

    if (filter_interface_name.empty() || current_ifindex == 0) {
        std::cerr << "Failed to determine interface from config on initial load." << std::endl;
        err = -1;
        goto cleanup_early;
    }

    link.reset(bpf_program__attach_xdp(skel->progs.xdp_filter, current_ifindex));
    if (!link) {
        std::cerr << "Failed to attach XDP program to ifindex " << current_ifindex << std::endl;
        goto cleanup_early;
    }    

    std::cout << "Successfully loaded and attached BPF program on interface " 
              << filter_interface_name << " (index " << current_ifindex << ")." << std::endl;

    // Bắt tín hiệu ngắt (Ctrl+C) để dọn dẹp
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Khởi tạo inotify
    inotify_fd = inotify_init();
    if (inotify_fd < 0) {
        std::cerr << "inotify_init error: " << strerror(errno) << std::endl;
        err = -1;
        goto cleanup_early;
    }

    watch_descriptor = inotify_add_watch(inotify_fd, config_file_path_abs.c_str(), 
                                         IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_DELETE_SELF | IN_MOVE_SELF);
    if (watch_descriptor < 0) {
        std::cerr << "inotify_add_watch error: " << strerror(errno) << std::endl;
        err = -1;
        goto cleanup_inotify;
    }

    std::cout << "Watching config file '" << config_file_path_abs << "' for changes..." << std::endl;
    std::cout << "Packet filter is running. Press Ctrl+C to exit." << std::endl;
    std::cout << "Run 'sudo cat /sys/kernel/debug/tracing/trace_pipe' to see kernel logs." << std::endl;

    while (!exiting) {
        fd_set rfds;
        struct timeval tv;
        int retval;

        FD_ZERO(&rfds);
        FD_SET(inotify_fd, &rfds);

        tv.tv_sec = 1;
        tv.tv_usec = 0;

        retval = select(inotify_fd + 1, &rfds, nullptr, nullptr, &tv);

        if (retval == -1) {
            if (errno == EINTR) continue;
            std::cerr << "select error: " << strerror(errno) << std::endl;
            err = -1;
            break;
        } else if (retval > 0) {
            if (FD_ISSET(inotify_fd, &rfds)) {
                ssize_t len = read(inotify_fd, buffer, BUF_LEN);
                if (len < 0) {
                    std::cerr << "read inotify_fd error: " << strerror(errno) << std::endl;
                    err = -1;
                    break;
                }

                for (char *p = buffer; p < buffer + len; ) {
                    struct inotify_event *event = reinterpret_cast<struct inotify_event *>(p);

                    if (event->mask & (IN_DELETE_SELF | IN_MOVE_SELF)) {
                        std::cout << "Config file '" << config_file_path_abs << "' deleted or moved. Attempting to re-watch..." << std::endl;
                        inotify_rm_watch(inotify_fd, watch_descriptor);
                        watch_descriptor = inotify_add_watch(inotify_fd, config_file_path_abs.c_str(), 
                                                             IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_DELETE_SELF | IN_MOVE_SELF);
                        if (watch_descriptor < 0) {
                            std::cerr << "inotify_add_watch (re-watch) error: " << strerror(errno) << std::endl;
                            std::cerr << "Failed to re-watch config file. Exiting." << std::endl;
                            exiting = true;
                            break;
                        }
                    } else if (event->mask & (IN_MODIFY | IN_CLOSE_WRITE)) {
                        std::cout << "Config file '" << config_file_path_abs << "' modified or written. Updating configuration..." << std::endl;
                        if (packet_filter::update_from_config() != 0) {
                            std::cerr << "Failed to update configuration from config. Continuing..." << std::endl;
                        }
                    }
                    p += EVENT_SIZE + event->len;
                }
            }
        }
    }

    // Print statistics when program exits
    print_statistics();

cleanup_inotify:
    if (inotify_fd >= 0) {
        if (watch_descriptor >= 0) {
            inotify_rm_watch(inotify_fd, watch_descriptor);
        }
        close(inotify_fd);
    }
    
cleanup_early:
    std::cout << "Detaching BPF program and cleaning up..." << std::endl;
    
    // The smart pointers will handle cleanup of skel and link
    packet_filter::free_subnet_list(current_blacklist_subnets);
    packet_filter::free_rate_limit_list(current_rate_limits);
    
    return err > 0 ? err : -err;
}