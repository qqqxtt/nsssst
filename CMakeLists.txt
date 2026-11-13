cmake_minimum_required(VERSION 3.20)
project(nsst LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Latency numbers from an unoptimised build are meaningless; default to Release.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED IMPORTED_TARGET libdpdk)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# User-space TCP/IP stack. Uses only rte_mbuf (no EAL), so tests run without hugepages or NICs.
add_library(protocol
    protocol/arp_cache.cpp protocol/arp_sender.cpp protocol/icmp.cpp protocol/stack.cpp
    protocol/tcp.cpp protocol/tcp_manager.cpp protocol/tcp_reassembly.cpp
    protocol/tcp_sender.cpp protocol/udp.cpp protocol/udp_registry.cpp)
target_include_directories(protocol PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}"
                                           "${CMAKE_CURRENT_SOURCE_DIR}/protocol")
target_link_libraries(protocol PUBLIC PkgConfig::DPDK)

# DPDK EAL, port, RX burst and TX queue ownership.
add_library(dpdk_runtime dpdk/runtime.cpp)
target_link_libraries(dpdk_runtime PUBLIC protocol PkgConfig::DPDK)

# TLS (OpenSSL handshake, direct TLS 1.3 record decryption) and WebSocket client over TCP.
add_library(wss_client wss/client.cpp wss/frame.cpp wss/tls13_reader.cpp)
target_include_directories(wss_client PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/wss")
target_link_libraries(wss_client PUBLIC protocol OpenSSL::SSL OpenSSL::Crypto)

# Binance BookTicker subscription and parser.
add_library(binance_market_data
    binance/book_ticker.cpp binance/connection.cpp binance/kernel_resolver.cpp)
target_link_libraries(binance_market_data PUBLIC wss_client Threads::Threads)

add_executable(nsst app/main.cpp)
target_link_libraries(nsst PRIVATE dpdk_runtime binance_market_data)

# Standalone micro-benchmark: SSL_read_ex versus direct TLS 1.3 record decryption.
add_executable(tls_direct_bench bench/tls_direct_bench.cpp)
target_link_libraries(tls_direct_bench PRIVATE wss_client)

include(CTest)
if(BUILD_TESTING)
    function(nsst_test name)
        add_executable(${name}_test tests/${name}_test.cpp)
        target_link_libraries(${name}_test PRIVATE ${ARGN})
        add_test(NAME ${name} COMMAND ${name}_test)
        set_tests_properties(${name} PROPERTIES TIMEOUT 10)
    endfunction()
    foreach(name arp arp_cache ipv4 icmp udp stack packet_ref
                 tcp_header tcp_passive tcp_active tcp_write tcp_ack_batch pending_tx stages)
        nsst_test(${name} protocol)
    endforeach()
    nsst_test(book_ticker binance_market_data)

    add_test(NAME tls_direct_bench_smoke COMMAND tls_direct_bench 100)
    add_test(NAME tls_direct_bench_chacha COMMAND tls_direct_bench 100 TLS_CHACHA20_POLY1305_SHA256)
    set_tests_properties(tls_direct_bench_smoke tls_direct_bench_chacha
                         PROPERTIES TIMEOUT 20)

    # In-memory WSS: two production TCP managers, a real OpenSSL server and the client.
    find_package(Python3 REQUIRED COMPONENTS Interpreter) # test drivers use the standard library only
    add_executable(wss_integration tests/wss_integration.cpp)
    target_link_libraries(wss_integration PRIVATE binance_market_data)
    foreach(mode echo wrong_host fragment bad_accept masked large book book_fragment book_tls12
                 book_budget book_batch book_openssl book_keyupdate book_fragment_aes128
                 book_fragment_chacha book_keyupdate_aes128 book_keyupdate_chacha)
        set(args --mode ${mode})
        if(mode STREQUAL "echo")
            set(args)
        elseif(mode STREQUAL "wrong_host")
            set(args --wrong-host)
        endif()
        add_test(NAME wss_${mode} COMMAND Python3::Interpreter
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_wss_test.py" $<TARGET_FILE:wss_integration> ${args})
        set_tests_properties(wss_${mode} PROPERTIES TIMEOUT 40)
    endforeach()

    add_test(NAME stages_report COMMAND Python3::Interpreter
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/stages_report_test.py"
        $<TARGET_FILE:stages_test> $<TARGET_FILE:nsst>)
    set_tests_properties(stages_report PROPERTIES TIMEOUT 10)
endif()
