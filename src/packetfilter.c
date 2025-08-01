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
#include <libgen.h> 

#define DEFAULT_CONFIG_FILE_RELATIVE "../src/config.txt"

// Define event buffer size for inotify
#define EVENT_SIZE (sizeof(struct inotify_event) + NAME_MAX + 1)
#define BUF_LEN (1024 * EVENT_SIZE)

static volatile bool exiting = false;
static int map_fd_blacklist; // File descriptor của blacklist map
static int map_fd_update_signal; // File descriptor của update signal map
static char *config_file_path = NULL; // Đường dẫn tới file config
static char *filter_interface_name = NULL; // Tên interface
static u_int32_t current_ifindex; // ifindex của interface

// Để theo dõi IP hiện tại trong blacklist map của kernel
// Cần một cấu trúc để lưu trữ IPs đã đọc từ file config
struct ip_node {
    __u32 ip_addr; // Network byte order
    struct ip_node *next;
};

static struct ip_node *current_blacklist_ips = NULL; // Linked list of current IPs

static void free_ip_list(struct ip_node *head) {
    struct ip_node *current = head;
    struct ip_node *next;
    while (current != NULL) {
        next = current->next;
        free(current);
        current = next;
    }
}

static void sig_handler(int sig) {
    exiting = true;
}

// Hàm thêm một IP vào blacklist map
// IP address ở dạng host byte order (ví dụ: 192.168.1.1)
static int add_to_blacklist(int map_fd, const char *ip_str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        fprintf(stderr, "Invalid IP address: %s\n", ip_str);
        return -1;
    }
    __u32 key = addr.s_addr; // Store in network byte order
    __u8 value = 1;
    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
        perror("Failed to update blacklist map");
        return -1;
    }
    printf("Added %s to blacklist BPF map.\n", ip_str);
    return 0;
}

// Hàm xóa một IP khỏi blacklist map
static int remove_from_blacklist(int map_fd, __u32 ip_addr_nbo) {
    if (bpf_map_delete_elem(map_fd, &ip_addr_nbo) != 0) {
        // Có thể thất bại nếu IP không tồn tại, không cần báo lỗi nghiêm trọng
        if (errno != ENOENT) { // ENOENT: No such file or directory (key not found)
            perror("Failed to delete from blacklist map");
            return -1;
        }
    }
    struct in_addr addr;
    addr.s_addr = ip_addr_nbo;
    printf("Removed %s from blacklist BPF map.\n", inet_ntoa(addr));
    return 0;
}

// Hàm đọc và cập nhật blacklist từ file config
static int update_blacklist_from_config(void) {
    FILE *file = fopen(config_file_path, "r");
    if (!file) {
        perror("Failed to open config file");
        return -1;
    }

    char line[256];
    char *token;
    char *saveptr;
    struct ip_node *new_ips_list = NULL;
    struct ip_node *new_ips_tail = NULL;
    char iface_name_buf[IF_NAMESIZE];
    char ip_list_buf[2048]; // Đủ lớn cho danh sách IP

    // Đọc tên interface và danh sách IP từ file config
    bool iface_found = false;
    bool ip_list_found = false;

    while (fgets(line, sizeof(line), file)) {
        // Xóa ký tự xuống dòng
        line[strcspn(line, "\n")] = 0;

        // Bỏ qua dòng trống hoặc dòng comment
        if (strlen(line) == 0 || line[0] == '#') {
            continue;
        }

        if (strstr(line, "interface=")) {
            iface_found = true;
            strncpy(iface_name_buf, line + strlen("interface="), sizeof(iface_name_buf) - 1);
            iface_name_buf[sizeof(iface_name_buf) - 1] = '\0';
            printf("Config: Interface name: %s\n", iface_name_buf);
        } else if (strstr(line, "ip_blacklist=")) {
            ip_list_found = true;
            strncpy(ip_list_buf, line + strlen("ip_blacklist="), sizeof(ip_list_buf) - 1);
            ip_list_buf[sizeof(ip_list_buf) - 1] = '\0';
            printf("Config: IP blacklist string: %s\n", ip_list_buf);
        }
    }
    fclose(file);

    if (!iface_found || !ip_list_found) {
        fprintf(stderr, "Error: Config file must contain 'interface=' and 'ip_blacklist='.\n");
        return -1;
    }

    // So sánh interface name
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
        return -1; // Yêu cầu restart nếu interface đổi
    }


    // Phân tích cú pháp chuỗi IP blacklist
    token = strtok_r(ip_list_buf, ",", &saveptr);
    while (token != NULL) {
        // Loại bỏ khoảng trắng thừa
        char *trimmed_token = token;
        while (*trimmed_token == ' ' || *trimmed_token == '\t') trimmed_token++;
        char *end = trimmed_token + strlen(trimmed_token) - 1;
        while (end > trimmed_token && (*end == ' ' || *end == '\t')) end--;
        *(end + 1) = '\0';

        if (strlen(trimmed_token) > 0) {
            struct in_addr addr;
            if (inet_pton(AF_INET, trimmed_token, &addr) == 1) {
                struct ip_node *new_node = malloc(sizeof(struct ip_node));
                if (!new_node) {
                    perror("Failed to allocate ip_node");
                    free_ip_list(new_ips_list);
                    return -1;
                }
                new_node->ip_addr = addr.s_addr; // Store in network byte order
                new_node->next = NULL;
                if (new_ips_list == NULL) {
                    new_ips_list = new_node;
                    new_ips_tail = new_node;
                } else {
                    new_ips_tail->next = new_node;
                    new_ips_tail = new_node;
                }
            } else {
                fprintf(stderr, "Warning: Invalid IP address '%s' in config file.\n", trimmed_token);
            }
        }
        token = strtok_r(NULL, ",", &saveptr);
    }

    // --- Bắt đầu quá trình đồng bộ hóa blacklist ---

    // 1. Xác định IPs cần xóa (có trong current_blacklist_ips nhưng không có trong new_ips_list)
    struct ip_node *current_ptr = current_blacklist_ips;
    while (current_ptr != NULL) {
        bool found = false;
        struct ip_node *new_ptr = new_ips_list;
        while (new_ptr != NULL) {
            if (current_ptr->ip_addr == new_ptr->ip_addr) {
                found = true;
                break;
            }
            new_ptr = new_ptr->next;
        }
        if (!found) {
            remove_from_blacklist(map_fd_blacklist, current_ptr->ip_addr);
        }
        current_ptr = current_ptr->next;
    }

    // 2. Xác định IPs cần thêm (có trong new_ips_list nhưng không có trong current_blacklist_ips)
    struct ip_node *new_ptr = new_ips_list;
    while (new_ptr != NULL) {
        bool found = false;
        current_ptr = current_blacklist_ips;
        while (current_ptr != NULL) {
            if (new_ptr->ip_addr == current_ptr->ip_addr) {
                found = true;
                break;
            }
            current_ptr = current_ptr->next;
        }
        if (!found) {
            struct in_addr addr;
            addr.s_addr = new_ptr->ip_addr;
            add_to_blacklist(map_fd_blacklist, inet_ntoa(addr));
        }
        new_ptr = new_ptr->next;
    }

    // 3. Cập nhật danh sách IP hiện tại
    free_ip_list(current_blacklist_ips); // Giải phóng danh sách cũ
    current_blacklist_ips = new_ips_list; // Gán danh sách mới

    // 4. Gửi tín hiệu cập nhật đến kernel (cho kernel biết blacklist đã thay đổi)
    // Dùng timestamp để đảm bảo giá trị thay đổi mỗi lần
    __u32 key = 0;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts); // Hoặc CLOCK_REALTIME
    __u64 timestamp = (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;    

    if (bpf_map_update_elem(map_fd_update_signal, &key, &timestamp, BPF_ANY) != 0) {
        perror("Failed to signal update to kernel via update_signal_map");
    } else {
        printf("Sent update signal to kernel.\n");
        // In ra thông báo từ user-space, đây là cách tốt nhất cho thông báo "blacklist updated"
        printf("\n--- IP Blacklist has been updated! ---\n");
    }

    return 0;
}


int main(int argc, char **argv) {
    struct packetfilter_bpf *skel;
    int err = 0;
    int inotify_fd;
    int watch_descriptor;
    char buffer[BUF_LEN];

    // ------------ config --------------------
    // Lấy đường dẫn của executable
    char executable_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", executable_path, sizeof(executable_path) - 1);
    if (len == -1) {
        perror("readlink /proc/self/exe");
        return 1;
    }
    executable_path[len] = '\0';

    // Lấy thư mục chứa executable
    char *dir_name = dirname(executable_path);
    if (!dir_name) {
        perror("dirname");
        return 1;
    }

    // Tạo đường dẫn tuyệt đối cho file config
    // config_file_path phải là một vùng nhớ đủ lớn để chứa đường dẫn tuyệt đối
    // Vì config_file_path là static char *, ta cần cấp phát động hoặc dùng mảng tĩnh lớn.
    // Dùng mảng tĩnh cục bộ và sau đó strdup vào config_file_path nếu cần thay đổi.
    static char full_config_path[PATH_MAX];
    snprintf(full_config_path, sizeof(full_config_path), "%s/%s", dir_name, DEFAULT_CONFIG_FILE_RELATIVE);

    config_file_path = full_config_path; // Gán đường dẫn tuyệt đối đã tạo

    printf("Using config file: %s\n", config_file_path);

    // Bỏ kiểm tra argc và gán trực tiếp đường dẫn file config
    // (nếu bạn muốn chỉ chấp nhận chạy không có tham số dòng lệnh)
    if (argc != 1) {
        fprintf(stderr, "Usage: %s\n", argv[0]);
        return 1;
    }
    // --------------------------------------

    // Mở, tải và xác thực chương trình BPF
    skel = packetfilter_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // Lấy file descriptor của map blacklist_map
    map_fd_blacklist = bpf_map__fd(skel->maps.blacklist_map);
    if (map_fd_blacklist < 0) {
        fprintf(stderr, "Failed to get blacklist map FD\n");
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

    // Sau khi update_blacklist_from_config() được gọi lần đầu,
    // filter_interface_name và current_ifindex đã có giá trị
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

    watch_descriptor = inotify_add_watch(inotify_fd, config_file_path, IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_DELETE_SELF | IN_MOVE_SELF);
    if (watch_descriptor < 0) {
        perror("inotify_add_watch");
        err = -1;
        goto cleanup_inotify;
    }

    printf("Watching config file '%s' for changes...\n", config_file_path);
    printf("Packet filter is running. Press Ctrl+C to exit.\n");
    printf("Run 'sudo cat /sys/kernel/debug/tracing/trace_pipe' to see kernel logs.\n");

    while (!exiting) {
        // Sử dụng select để đợi cả inotify events và tín hiệu dừng
        fd_set rfds;
        struct timeval tv;
        int retval;

        FD_ZERO(&rfds);
        FD_SET(inotify_fd, &rfds);

        // Thiết lập timeout để vòng lặp không bị chặn vĩnh viễn
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        retval = select(inotify_fd + 1, &rfds, NULL, NULL, &tv);

        if (retval == -1) {
            if (errno == EINTR) continue; // Bị ngắt bởi tín hiệu, tiếp tục vòng lặp
            perror("select");
            err = -1;
            break;
        } else if (retval > 0) {
            if (FD_ISSET(inotify_fd, &rfds)) {
                // Đọc sự kiện inotify
                ssize_t len = read(inotify_fd, buffer, BUF_LEN);
                if (len < 0) {
                    perror("read inotify_fd");
                    err = -1;
                    break;
                }

                // Xử lý các sự kiện
                for (char *p = buffer; p < buffer + len; ) {
                    struct inotify_event *event = (struct inotify_event *)p;

                    // Nếu file bị xóa hoặc di chuyển (rename), cần thêm lại watch
                    if (event->mask & (IN_DELETE_SELF | IN_MOVE_SELF)) {
                        fprintf(stdout, "Config file '%s' deleted or moved. Attempting to re-watch...\n", config_file_path);
                        inotify_rm_watch(inotify_fd, watch_descriptor); // Xóa watch cũ
                        watch_descriptor = inotify_add_watch(inotify_fd, config_file_path, IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_DELETE_SELF | IN_MOVE_SELF);
                        if (watch_descriptor < 0) {
                            perror("inotify_add_watch (re-watch)");
                            fprintf(stderr, "Failed to re-watch config file. Exiting.\n");
                            exiting = true;
                            err = -1;
                            break;
                        }
                    } else if (event->mask & (IN_MODIFY | IN_CLOSE_WRITE)) {
                        printf("Config file '%s' modified or written. Updating blacklist...\n", config_file_path);
                        if (update_blacklist_from_config() != 0) {
                            fprintf(stderr, "Failed to update blacklist from config. Continuing...\n");
                            // Có thể chọn exit ở đây nếu lỗi nghiêm trọng
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
    free_ip_list(current_blacklist_ips);
    return -err;
}