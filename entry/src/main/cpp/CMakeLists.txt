# Set the minimum required version of CMake to 3.4.1
cmake_minimum_required(VERSION 3.4.1)

project(OTPCUTILS)

# Define the variable NATIVERENDER_ROOT_PATH as the root path of the current source code
set(NATIVERENDER_ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR})

# Add the header file path to the project
include_directories(
    ${NATIVERENDER_ROOT_PATH}
    ${NATIVERENDER_ROOT_PATH}/include
    ${NATIVERENDER_ROOT_PATH}/nanopb
    ${NATIVERENDER_ROOT_PATH}/proto
)

add_library(otpcutils SHARED main.cpp nanopb/pb_common.c nanopb/pb_decode.c nanopb/pb_encode.c proto/google_auth.pb.c)

target_link_libraries(otpcutils PUBLIC libace_napi.z.so libc++.a)
target_link_libraries(otpcutils PUBLIC libhilog_ndk.z.so)