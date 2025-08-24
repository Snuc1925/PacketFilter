# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/home/maimanh/PacketFilter/build/prometheus-cpp/src/prometheus-cpp-ext"
  "/home/maimanh/PacketFilter/build/prometheus-cpp/src/prometheus-cpp-ext-build"
  "/home/maimanh/PacketFilter/build/prometheus-cpp"
  "/home/maimanh/PacketFilter/build/prometheus-cpp/tmp"
  "/home/maimanh/PacketFilter/build/prometheus-cpp/src/prometheus-cpp-ext-stamp"
  "/home/maimanh/PacketFilter/build/prometheus-cpp/src"
  "/home/maimanh/PacketFilter/build/prometheus-cpp/src/prometheus-cpp-ext-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/maimanh/PacketFilter/build/prometheus-cpp/src/prometheus-cpp-ext-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/maimanh/PacketFilter/build/prometheus-cpp/src/prometheus-cpp-ext-stamp${cfgdir}") # cfgdir has leading slash
endif()
