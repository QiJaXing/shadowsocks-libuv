cmake_minimum_required(VERSION 3.3)
project(shadowsocks_libuv)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES
    ss-local/include/shadow.h
    ss-local/src/client.c
    ss-local/src/crypt.c
    ss-local/src/handshake.c
    ss-local/src/remote.c
    ss-local/src/shadow.c
    ss-local/local.c
    config.h
    encrypt.c
    encrypt.h
    server.c
    server.h
    utils.c
    utils.h)

add_executable(shadowsocks_libuv ${SOURCE_FILES})