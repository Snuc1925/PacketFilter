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

#define DEFAULT_CONFIG_FILE_RELATIVE "../src/config.txt"

static volatile bool exiting = false;
static int map_fd_blacklist_subnets; // File descriptor của blacklist map (giờ là LPM Trie)
static int map_fd_update_signal;     // File descriptor của update signal map
static char *config_file_path_abs = NULL; // Đường dẫn tuyệt đối tới file config
static char *filter_interface_name = NULL; // Tên interface
static u_int32_t current_ifindex; // ifindex của interface
static struct subnet_node *current_blacklist_subnets = NULL; // Linked list of current subnets

static void sig_handler(int sig) {
    exiting = true;
}

int main(int argc, char **argv) {
    struct packetfilter_bpf *skel;
    struct bpf_link *link;
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

    // Initialize the subnet blacklist module
    subnet_blacklist_init(map_fd_blacklist_subnets, map_fd_update_signal, 
                         &config_file_path_abs, &filter_interface_name, 
                         &current_ifindex, &current_blacklist_subnets);

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

    link = bpf_program__attach_xdp(skel->progs.xdp_filter, current_ifindex);
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