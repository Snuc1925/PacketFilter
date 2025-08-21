// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "packetfilter.skel.h" // File skeleton được tạo tự động
#include <errno.h> // For errno
#include <sys/inotify.h> // For inotify
#include <limits.h> // For PATH_MAX
#include <time.h> // For clock_gettime
#include <libgen.h> // For dirname

// Include the subnet blacklist header
#include "subnet_blacklist.h"

// Define event buffer size for inotify
#define EVENT_SIZE (sizeof(struct inotify_event) + NAME_MAX + 1)
#define BUF_LEN (1024 * EVENT_SIZE)
#define MAX_ENTRIES 1024  // Maximum number of tracked IPs

#define DEFAULT_CONFIG_FILE_RELATIVE "../src/config.txt"

// Structure for packet statistics by IP (must match the BPF struct)
struct packet_stats {
    __u64 dropped;  // Number of dropped packets
    __u64 passed;   // Number of passed packets
};

static volatile bool exiting = false;
static int map_fd_blacklist_subnets; // File descriptor của blacklist map (giờ là LPM Trie)
static int map_fd_update_signal;     // File descriptor của update signal map
static int map_fd_ip_stats;          // File descriptor for IP statistics map
static int map_fd_global_stats;      // File descriptor for global statistics map
static char *config_file_path_abs = NULL; // Đường dẫn tuyệt đối tới file config
static char *filter_interface_name = NULL; // Tên interface
static u_int32_t current_ifindex; // ifindex của interface
static struct subnet_node *current_blacklist_subnets = NULL; // Linked list of current subnets

static void sig_handler(int sig) {
    exiting = true;
}

// Function to print packet statistics when program exits
void print_statistics() {
    printf("\n-------- Packet Filter Statistics --------\n");
    
    // Print global statistics
    __u32 key = 0;
    __u64 dropped = 0;
    if (bpf_map_lookup_elem(map_fd_global_stats, &key, &dropped) == 0) {
        key = 1;
        __u64 passed = 0;
        if (bpf_map_lookup_elem(map_fd_global_stats, &key, &passed) == 0) {
            printf("Total packets: %llu (Dropped: %llu, Passed: %llu)\n", 
                dropped + passed, dropped, passed);
        }
    }
    
    // Collect per-IP statistics
    struct ip_entry {
        __u32 ip;
        struct packet_stats stats;
    };
    struct ip_entry entries[1024]; // tùy chỉnh nếu map lớn
    int count = 0;

    __u32 ip_key = 0;
    struct packet_stats stats;

    while (bpf_map_get_next_key(map_fd_ip_stats, count == 0 ? NULL : &ip_key, &ip_key) == 0) {
        if (bpf_map_lookup_elem(map_fd_ip_stats, &ip_key, &stats) == 0 &&
            (stats.dropped > 0 || stats.passed > 0)) {
            entries[count].ip = ip_key;
            entries[count].stats = stats;
            count++;
        }
    }

    if (count == 0) {
        printf("\nNo packet statistics recorded.\n");
        return;
    }

    // Sort by dropped packets (descending)
    qsort(entries, count, sizeof(struct ip_entry), 
        [](const void *a, const void *b) {
            const struct ip_entry *ia = (const struct ip_entry *)a;
            const struct ip_entry *ib = (const struct ip_entry *)b;
            if (ia->stats.dropped < ib->stats.dropped) return 1;
            if (ia->stats.dropped > ib->stats.dropped) return -1;
            return 0;
        }
    );

    // Open file for writing
    FILE *f = fopen("stats.txt", "w");
    if (!f) {
        perror("fopen");
        return;
    }

    // Print and write results
    fprintf(f, "%-15s  %10s  %10s  %10s\n", "IP Address", "Dropped", "Passed", "Total");
    fprintf(f, "---------------------------------------------------\n");

    for (int i = 0; i < count; i++) {
        struct in_addr addr;
        addr.s_addr = entries[i].ip;
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

        fprintf(f, "%-15s  %10llu  %10llu  %10llu\n",
            ip_str,
            entries[i].stats.dropped,
            entries[i].stats.passed,
            entries[i].stats.dropped + entries[i].stats.passed);
    }

    fclose(f);

    printf("Per-IP statistics written to stats.txt\n");
}


int main(int argc, char **argv) {
    struct packetfilter_bpf *skel = NULL;
    struct bpf_link *link = NULL;
    int err = 0;
    int inotify_fd = -1;
    int watch_descriptor = -1;
    char buffer[BUF_LEN];

    // Lấy đường dẫn của executable
    char executable_path_buf[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", executable_path_buf, sizeof(executable_path_buf) - 1);
    if (len == -1) {
        perror("readlink /proc/self/exe");
        return 1;
    }
    executable_path_buf[len] = '\0';

    // Tạo một bản sao để dirname có thể chỉnh sửa
    char *executable_path_copy = strdup(executable_path_buf);
    if (!executable_path_copy) {
        perror("strdup");
        return 1;
    }
    char *dir_name = dirname(executable_path_copy);
    if (!dir_name) {
        perror("dirname");
        free(executable_path_copy); // Giải phóng bộ nhớ đã cấp phát
        return 1;
    }

    // full_config_path cần phải là vùng nhớ ổn định, ví dụ một mảng static hoặc cấp phát động
    // và gán cho config_file_path_abs
    config_file_path_abs = (char*)malloc(PATH_MAX);
    if (!config_file_path_abs) {
        perror("malloc for config_file_path_abs");
        free(executable_path_copy);
        return 1;
    }
    snprintf(config_file_path_abs, PATH_MAX, "%s/%s", dir_name, DEFAULT_CONFIG_FILE_RELATIVE);
    free(executable_path_copy); // Giải phóng bản copy sau khi dirname đã sử dụng

    printf("Using config file: %s\n", config_file_path_abs);

    if (argc != 1) {
        fprintf(stderr, "Usage: %s\n", argv[0]);
        err = 1;
        goto cleanup_early;
    }

    // Mở, tải và xác thực chương trình BPF
    skel = packetfilter_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        err = 1;
        goto cleanup_early;
    }

    // Lấy file descriptor của map blacklist_subnets_map
    map_fd_blacklist_subnets = bpf_map__fd(skel->maps.blacklist_subnets_map);
    if (map_fd_blacklist_subnets < 0) {
        fprintf(stderr, "Failed to get blacklist_subnets_map FD\n");
        err = -1;
        goto cleanup_early;
    }

    // Lấy file descriptor của map update_signal_map
    map_fd_update_signal = bpf_map__fd(skel->maps.update_signal_map);
    if (map_fd_update_signal < 0) {
        fprintf(stderr, "Failed to get update_signal_map FD\n");
        err = -1;
        goto cleanup_early;
    }
    
    // Get file descriptors for statistics maps
    map_fd_ip_stats = bpf_map__fd(skel->maps.ip_stats_map);
    if (map_fd_ip_stats < 0) {
        fprintf(stderr, "Failed to get ip_stats_map FD\n");
        err = -1;
        goto cleanup_early;
    }
    
    map_fd_global_stats = bpf_map__fd(skel->maps.global_stats_map);
    if (map_fd_global_stats < 0) {
        fprintf(stderr, "Failed to get global_stats_map FD\n");
        err = -1;
        goto cleanup_early;
    }
    
    // Initialize global counters to zero
    {
        __u32 key = 0;  // dropped counter
        __u64 value = 0;
        if (bpf_map_update_elem(map_fd_global_stats, &key, &value, BPF_ANY) != 0) {
            perror("Failed to initialize dropped packets counter");
        }
        
        key = 1;  // passed counter
        if (bpf_map_update_elem(map_fd_global_stats, &key, &value, BPF_ANY) != 0) {
            perror("Failed to initialize passed packets counter");
        }
    }

    // Initialize the subnet blacklist module
    subnet_blacklist_init(map_fd_blacklist_subnets, map_fd_update_signal, 
                         &config_file_path_abs, &filter_interface_name, 
                         &current_ifindex, &current_blacklist_subnets);

    // Đọc cấu hình lần đầu và attach XDP
    if (update_blacklist_from_config() != 0) {
        err = -1;
        goto cleanup_early;
    }

    if (!filter_interface_name || current_ifindex == 0) {
        fprintf(stderr, "Failed to determine interface from config on initial load.\n");
        err = -1;
        goto cleanup_early;
    }

    link = bpf_program__attach_xdp(skel->progs.xdp_filter, current_ifindex);
    if (!link) {
        fprintf(stderr, "Failed to attach XDP program to ifindex %d\n", current_ifindex);
        goto cleanup_early;
    }    

    printf("Successfully loaded and attached BPF program on interface %s (index %u).\n", filter_interface_name, current_ifindex);

    // Bắt tín hiệu ngắt (Ctrl+C) để dọn dẹp
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Khởi tạo inotify
    inotify_fd = inotify_init();
    if (inotify_fd < 0) {
        perror("inotify_init");
        err = -1;
        goto cleanup_early;
    }

    watch_descriptor = inotify_add_watch(inotify_fd, config_file_path_abs, IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_DELETE_SELF | IN_MOVE_SELF);
    if (watch_descriptor < 0) {
        perror("inotify_add_watch");
        err = -1;
        goto cleanup_inotify;
    }

    printf("Watching config file '%s' for changes...\n", config_file_path_abs);
    printf("Packet filter is running. Press Ctrl+C to exit.\n");
    printf("Run 'sudo cat /sys/kernel/debug/tracing/trace_pipe' to see kernel logs.\n");

    while (!exiting) {
        fd_set rfds;
        struct timeval tv;
        int retval;

        FD_ZERO(&rfds);
        FD_SET(inotify_fd, &rfds);

        tv.tv_sec = 1;
        tv.tv_usec = 0;

        retval = select(inotify_fd + 1, &rfds, NULL, NULL, &tv);

        if (retval == -1) {
            if (errno == EINTR) continue;
            perror("select");
            err = -1;
            break;
        } else if (retval > 0) {
            if (FD_ISSET(inotify_fd, &rfds)) {
                ssize_t len = read(inotify_fd, buffer, BUF_LEN);
                if (len < 0) {
                    perror("read inotify_fd");
                    err = -1;
                    break;
                }

                for (char *p = buffer; p < buffer + len; ) {
                    struct inotify_event *event = (struct inotify_event *)p;

                    if (event->mask & (IN_DELETE_SELF | IN_MOVE_SELF)) {
                        fprintf(stdout, "Config file '%s' deleted or moved. Attempting to re-watch...\n", config_file_path_abs);
                        inotify_rm_watch(inotify_fd, watch_descriptor);
                        watch_descriptor = inotify_add_watch(inotify_fd, config_file_path_abs, IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_DELETE_SELF | IN_MOVE_SELF);
                        if (watch_descriptor < 0) {
                            perror("inotify_add_watch (re-watch)");
                            fprintf(stderr, "Failed to re-watch config file. Exiting.\n");
                            exiting = true;
                            break;
                        }
                    } else if (event->mask & (IN_MODIFY | IN_CLOSE_WRITE)) {
                        printf("Config file '%s' modified or written. Updating blacklist...\n", config_file_path_abs);
                        if (update_blacklist_from_config() != 0) {
                            fprintf(stderr, "Failed to update blacklist from config. Continuing...\n");
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
    printf("Detaching BPF program and cleaning up...\n");
    if (skel) {
        packetfilter_bpf__destroy(skel);
    }
    free(filter_interface_name);
    free_subnet_list(current_blacklist_subnets);
    free(config_file_path_abs); // Giải phóng bộ nhớ cho đường dẫn config tuyệt đối
    return err > 0 ? err : -err;
}