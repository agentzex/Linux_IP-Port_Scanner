cmake_minimum_required(VERSION 2.8)
project(network_scanner)

set(CMAKE_CXX_STANDARD 17)
include(FindPCAP.cmake)
set(CMAKE_CXX_FLAGS -pthread)
set(SOURCE_FILES main.cpp)
add_executable(network_scanner main.cpp ifaces.c  misc.c oui.h data_reply.c data_request.c data_unique.c found_ips.cpp found_ips.h port_scanner.cpp ports_scanner.h)
target_link_libraries(network_scanner ${PCAP_LIBRARY})
