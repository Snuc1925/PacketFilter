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

// Define event buffer size for inotify
#define EVENT_SIZE (sizeof(struct inotify_event) + NAME_MAX + 1)
#define BUF_LEN (1024 * EVENT_SIZE)

#define DEFAULT_CONFIG_FILE_RELATIVE "../src/config.txt"

static volatile bool exiting = false;
static int map_fd_blacklist_subnets; // File descriptor của blacklist map (giờ là LPM Trie)
static int map_fd_update_signal;     // File descriptor của update signal map
static char *config_file_path_abs = NULL; // Đường dẫn tuyệt đối tới file config
static char *filter_interface_name = NULL; // Tên interface
static u_int32_t current_ifindex; // ifindex của interface

// Cấu trúc key cho LPM Trie map (cần khớp với định nghĩa trong BPF code)
struct bpf_lpm_trie_key {
    __u32 prefixlen;
    __u32 ip; // IPv4 address (network byte order)
};

// Để theo dõi Subnet hiện tại trong blacklist map của kernel
struct subnet_node {
    struct bpf_lpm_trie_key key;
    struct subnet_node *next;
};

static struct subnet_node *current_blacklist_subnets = NULL; // Linked list of current subnets

static void free_subnet_list(struct subnet_node *head) {
    struct subnet_node *current = head;
    struct subnet_node *next;
    while (current != NULL) {
        next = current->next;
        free(current);
        current = next;
    }
}

static void sig_handler(int sig) {
    exiting = true;
}

// Hàm thêm một subnet vào blacklist map
// subnet_str ví dụ "192.168.1.0/24"
static int add_to_blacklist(int map_fd, const char *subnet_str) {
    struct in_addr addr;
    char ip_str[INET_ADDRSTRLEN];   
    int prefixlen;
    char *slash = strchr((char *)subnet_str, '/');

    if (slash) {
        // Có prefixlen
        strncpy(ip_str, subnet_str, slash - subnet_str);
        ip_str[slash - subnet_str] = '\0';
        prefixlen = atoi(slash + 1);
    } else {
        // Chỉ là IP đơn lẻ, coi như /32
        strncpy(ip_str, subnet_str, sizeof(ip_str)  - 1);
        ip_str[sizeof(ip_str) - 1] = '\0';
        prefixlen = 32;
    }

    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        fprintf(stderr, "Invalid IP address in subnet: %s\n", subnet_str);
        return -1;
    }

    if (prefixlen < 0 || prefixlen > 32) {
        fprintf(stderr, "Invalid prefix length: %d in subnet: %s\n", prefixlen, subnet_str);
        return -1;
    }

    struct bpf_lpm_trie_key key = {
        .prefixlen = (__u32)prefixlen,
        .ip = addr.s_addr // IP mạng (network byte order)
    };
    __u8 value = 1; // Giá trị placeholder

    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
        perror("Failed to update blacklist subnet map");
        return -1;
    }
    printf("Added %s to blacklist BPF map.\n", subnet_str);
    return 0;
}

// Hàm xóa một subnet khỏi blacklist map
static int remove_from_blacklist(int map_fd, struct bpf_lpm_trie_key *key) {
    if (bpf_map_delete_elem(map_fd, key) != 0) {
        if (errno != ENOENT) {
            perror("Failed to delete from blacklist subnet map");
            return -1;
        }
    }
    struct in_addr addr;
    addr.s_addr = key->ip;
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
    printf("Removed %s/%u from blacklist BPF map.\n", ip_str, key->prefixlen);
    return 0;
}

// Hàm đọc và cập nhật blacklist từ file config
static int update_blacklist_from_config(void) {
    FILE *file = fopen(config_file_path_abs, "r");
    if (!file) {
        perror("Failed to open config file");
        return -1;
    }

    char line[256];
    char *token;
    char *saveptr;
    struct subnet_node *new_subnets_list = NULL;
    struct subnet_node *new_subnets_tail = NULL;
    char iface_name_buf[IF_NAMESIZE];
    char subnet_list_buf[2048]; // Đủ lớn cho danh sách subnet

    bool iface_found = false;
    bool subnet_list_found = false;

    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = 0; // Remove newline

        if (strlen(line) == 0 || line[0] == '#') {
            continue;
        }

        if (strstr(line, "interface=")) {
            iface_found = true;
            strncpy(iface_name_buf, line + strlen("interface="), sizeof(iface_name_buf) - 1);
            iface_name_buf[sizeof(iface_name_buf) - 1] = '\0';
            printf("Config: Interface name: %s\n", iface_name_buf);
        } else if (strstr(line, "ip_blacklist=")) {
            subnet_list_found = true;
            strncpy(subnet_list_buf, line + strlen("ip_blacklist="), sizeof(subnet_list_buf) - 1);
            subnet_list_buf[sizeof(subnet_list_buf) - 1] = '\0';
            printf("Config: IP blacklist string: %s\n", subnet_list_buf);
        }
    }
    fclose(file);

    if (!iface_found || !subnet_list_found) {
        fprintf(stderr, "Error: Config file must contain 'interface=' and 'ip_blacklist='.\n");
        return -1;
    }

    // So sánh interface name (chỉ được đặt 1 lần lúc khởi động)
    if (filter_interface_name == NULL) { // Lần đầu đọc config
        filter_interface_name = strdup(iface_name_buf);
        if (!filter_interface_name) {
            perror("strdup");
            return -1;
        }
        current_ifindex = if_nametoindex(filter_interface_name);
        if (!current_ifindex) {
            perror("if_nametoindex");
            return -1;
        }
        printf("Initial interface set to %s (index %u).\n", filter_interface_name, current_ifindex);
    } else if (strcmp(filter_interface_name, iface_name_buf) != 0) {
        fprintf(stderr, "Error: Changing interface name (%s to %s) dynamically is not supported. Please restart.\n",
                filter_interface_name, iface_name_buf);
        return -1;
    }

    // Phân tích cú pháp chuỗi IP blacklist / subnet
    token = strtok_r(subnet_list_buf, ",", &saveptr);
    while (token != NULL) {
        char *trimmed_token = token;
        while (*trimmed_token == ' ' || *trimmed_token == '\t') trimmed_token++;
        char *end = trimmed_token + strlen(trimmed_token) - 1;
        while (end > trimmed_token && (*end == ' ' || *end == '\t')) end--;
        *(end + 1) = '\0';

        if (strlen(trimmed_token) > 0) {
            struct in_addr addr;
            char ip_only[INET_ADDRSTRLEN];
            int prefixlen;
            char *slash_ptr = strchr(trimmed_token, '/');

            if (slash_ptr) {
                strncpy(ip_only, trimmed_token, slash_ptr - trimmed_token);
                ip_only[slash_ptr - trimmed_token] = '\0';
                prefixlen = atoi(slash_ptr + 1);
            } else {
                strncpy(ip_only, trimmed_token, sizeof(ip_only) - 1);
                ip_only[sizeof(ip_only) - 1] = '\0';
                prefixlen = 32; // Mặc định là /32 nếu không có subnet mask
            }

            if (inet_pton(AF_INET, ip_only, &addr) == 1) {
                if (prefixlen >= 0 && prefixlen <= 32) {
                    struct subnet_node *new_node = malloc(sizeof(struct subnet_node));
                    if (!new_node) {
                        perror("Failed to allocate subnet_node");
                        free_subnet_list(new_subnets_list);
                        return -1;
                    }
                    new_node->key.ip = addr.s_addr; // Network byte order
                    new_node->key.prefixlen = (__u32)prefixlen;
                    new_node->next = NULL;
                    if (new_subnets_list == NULL) {
                        new_subnets_list = new_node;
                        new_subnets_tail = new_node;
                    } else {
                        new_subnets_tail->next = new_node;
                        new_subnets_tail = new_node;
                    }
                } else {
                    fprintf(stderr, "Warning: Invalid prefix length for '%s' in config file.\n", trimmed_token);
                }
            } else {
                fprintf(stderr, "Warning: Invalid IP address '%s' in config file.\n", ip_only);
            }
        }
        token = strtok_r(NULL, ",", &saveptr);
    }

    // --- Bắt đầu quá trình đồng bộ hóa blacklist ---

    // 1. Xác định subnets cần xóa (có trong current_blacklist_subnets nhưng không có trong new_subnets_list)
    struct subnet_node *current_ptr = current_blacklist_subnets;
    while (current_ptr != NULL) {
        bool found = false;
        struct subnet_node *new_ptr = new_subnets_list;
        while (new_ptr != NULL) {
            if (current_ptr->key.ip == new_ptr->key.ip &&
                current_ptr->key.prefixlen == new_ptr->key.prefixlen) {
                found = true;
                break;
            }
            new_ptr = new_ptr->next;
        }
        if (!found) {
            remove_from_blacklist(map_fd_blacklist_subnets, ¤t_ptr->key);
        }
        current_ptr = current_ptr->next;
    }

    // 2. Xác định subnets cần thêm (có trong new_subnets_list nhưng không có trong current_blacklist_subnets)
    struct subnet_node *new_ptr = new_subnets_list;
    while (new_ptr != NULL) {
        bool found = false;
        current_ptr = current_blacklist_subnets;
        while (current_ptr != NULL) {
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
    free_subnet_list(current_blacklist_subnets); // Giải phóng danh sách cũ
    current_blacklist_subnets = new_subnets_list; // Gán danh sách mới

    // 4. Gửi tín hiệu cập nhật đến kernel (cho kernel biết blacklist đã thay đổi)
    __u32 key = 0;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    __u64 timestamp = (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    if (bpf_map_update_elem(map_fd_update_signal, &key, ×tamp, BPF_ANY) != 0) {
        perror("Failed to signal update to kernel via update_signal_map");
    } else {
        printf("Sent update signal to kernel.\n");
        printf("\n--- IP Subnet Blacklist has been updated! ---\n");
    }

    return 0;
}


int main(int argc, char **argv) {
    struct packetfilter_bpf *skel;
    int err = 0;
    int inotify_fd;
    int watch_descriptor;
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
        return 1;
    }

    // Mở, tải và xác thực chương trình BPF
    skel = packetfilter_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // Lấy file descriptor của map blacklist_subnets_map
    map_fd_blacklist_subnets = bpf_map__fd(skel->maps.blacklist_subnets_map);
    if (map_fd_blacklist_subnets < 0) {
        fprintf(stderr, "Failed to get blacklist_subnets_map FD\n");
        err = -1;
        goto cleanup;
    }

    // Lấy file descriptor của map update_signal_map
    map_fd_update_signal = bpf_map__fd(skel->maps.update_signal_map);
    if (map_fd_update_signal < 0) {
        fprintf(stderr, "Failed to get update_signal_map FD\n");
        err = -1;
        goto cleanup;
    }

    // Đọc cấu hình lần đầu và attach XDP
    if (update_blacklist_from_config() != 0) {
        err = -1;
        goto cleanup;
    }

    if (!filter_interface_name || current_ifindex == 0) {
        fprintf(stderr, "Failed to determine interface from config on initial load.\n");
        err = -1;
        goto cleanup;
    }

    struct bpf_link *link = bpf_program__attach_xdp(skel->progs.xdp_filter, current_ifindex);
    if (!link) {
        fprintf(stderr, "Failed to attach XDP program to ifindex %d\n", current_ifindex);
        goto cleanup;
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
        goto cleanup;
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

cleanup_inotify:
    if (inotify_fd >= 0) {
        if (watch_descriptor >= 0) {
            inotify_rm_watch(inotify_fd, watch_descriptor);
        }
        close(inotify_fd);
    }
cleanup:
    printf("Detaching BPF program and cleaning up...\n");
    packetfilter_bpf__destroy(skel);
    free(filter_interface_name);
    free_subnet_list(current_blacklist_subnets);
    free(config_file_path_abs); // Giải phóng bộ nhớ cho đường dẫn config tuyệt đối
    return -err;
}