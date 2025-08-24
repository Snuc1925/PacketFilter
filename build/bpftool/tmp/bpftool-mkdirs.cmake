# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/home/maimanh/PacketFilter/src/../bpftool/src"
  "/home/maimanh/PacketFilter/build/bpftool/src/bpftool-build"
  "/home/maimanh/PacketFilter/build/bpftool"
  "/home/maimanh/PacketFilter/build/bpftool/tmp"
  "/home/maimanh/PacketFilter/build/bpftool/src/bpftool-stamp"
  "/home/maimanh/PacketFilter/build/bpftool/src"
  "/home/maimanh/PacketFilter/build/bpftool/src/bpftool-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/maimanh/PacketFilter/build/bpftool/src/bpftool-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/maimanh/PacketFilter/build/bpftool/src/bpftool-stamp${cfgdir}") # cfgdir has leading slash
endif()
