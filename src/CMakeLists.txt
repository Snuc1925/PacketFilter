# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

cmake_minimum_required(VERSION 3.16)
project(PacketFilter C CXX)  # Added CXX since prometheus-cpp is C++

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Add prometheus-cpp as an external project ---
include(ExternalProject)
ExternalProject_Add(prometheus-cpp-ext
  PREFIX prometheus-cpp
  GIT_REPOSITORY https://github.com/jupp0r/prometheus-cpp.git
  GIT_TAG master  # You can specify a specific tag/commit here for stability
  CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/prometheus-cpp
    -DENABLE_TESTING=OFF
    -DUSE_THIRDPARTY_LIBRARIES=ON  # Build with bundled dependencies
    -DENABLE_PUSH=OFF  # Enable if you need push gateway support
  STEP_TARGETS build
)

# Set up include directories and libraries for prometheus-cpp
set(PROMETHEUS_CPP_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/prometheus-cpp/include)
set(PROMETHEUS_CPP_LIBRARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/prometheus-cpp/lib)

# --- Các bước thiết lập giống hệt libbpf-bootstrap ---

# Cho cmake biết nơi tìm module BpfObject
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../tools/cmake)

# Build libbpf đi kèm
ExternalProject_Add(libbpf
  PREFIX libbpf
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../libbpf/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make
    BUILD_STATIC_ONLY=1
    OBJDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf
    DESTDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf
    INCLUDEDIR=
    LIBDIR=
    UAPIDIR=
    install install_uapi_headers
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
)

# Build bpftool đi kèm
ExternalProject_Add(bpftool
  PREFIX bpftool
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../bpftool/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make bootstrap
    OUTPUT=${CMAKE_CURRENT_BINARY_DIR}/bpftool/
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
)

# Xác định kiến trúc CPU
if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "x86_64")
  set(ARCH "x86")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "aarch64")
  set(ARCH "arm64")
# Thêm các kiến trúc khác nếu cần
endif()

# Thiết lập các biến đầu vào cho BpfObject
set(BPFOBJECT_BPFTOOL_EXE ${CMAKE_CURRENT_BINARY_DIR}/bpftool/bootstrap/bpftool)
set(BPFOBJECT_VMLINUX_H ${CMAKE_CURRENT_SOURCE_DIR}/../vmlinux.h/include/${ARCH}/vmlinux.h)
set(LIBBPF_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/libbpf)
set(LIBBPF_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf.a)
find_package(BpfObject REQUIRED)

# --- Phần tùy chỉnh cho dự án PacketFilter ---

# 1. Tạo skeleton từ file .bpf.c
bpf_object(packetfilter packetfilter.bpf.c)
# Đảm bảo skeleton được build sau khi libbpf và bpftool được build
add_dependencies(packetfilter_skel libbpf-build bpftool-build)

# 2. Tạo file thực thi từ file .c
add_executable(packetfilter 
  packetfilter.cpp
  subnet_blacklist.cpp
)

# Add the prometheus-cpp include directories
target_include_directories(packetfilter PRIVATE ${PROMETHEUS_CPP_INCLUDE_DIR})
target_link_directories(packetfilter PRIVATE ${PROMETHEUS_CPP_LIBRARY_DIR})

# 3. Liên kết file thực thi với skeleton và các thư viện cần thiết
target_link_libraries(packetfilter PRIVATE
  packetfilter_skel
  prometheus-cpp-core
  prometheus-cpp-pull
)

# Make sure prometheus-cpp is built before our main target
add_dependencies(packetfilter prometheus-cpp-ext)