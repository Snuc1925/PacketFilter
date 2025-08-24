# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/home/maimanh/PacketFilter/src/../libbpf/src"
  "/home/maimanh/PacketFilter/build/libbpf/src/libbpf-build"
  "/home/maimanh/PacketFilter/build/libbpf"
  "/home/maimanh/PacketFilter/build/libbpf/tmp"
  "/home/maimanh/PacketFilter/build/libbpf/src/libbpf-stamp"
  "/home/maimanh/PacketFilter/build/libbpf/src"
  "/home/maimanh/PacketFilter/build/libbpf/src/libbpf-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/maimanh/PacketFilter/build/libbpf/src/libbpf-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/maimanh/PacketFilter/build/libbpf/src/libbpf-stamp${cfgdir}") # cfgdir has leading slash
endif()
