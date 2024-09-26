# Set the minimum required version of CMake to 3.4.1
cmake_minimum_required(VERSION 3.4.1)

project(TOTP_MCU)

# Define the variable NATIVERENDER_ROOT_PATH as the root path of the current source code
set(NATIVERENDER_ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR})

# Add the header file path to the project
include_directories(
    ${NATIVERENDER_ROOT_PATH}
    ${NATIVERENDER_ROOT_PATH}/include
)

add_library(totp_mcu SHARED totp_mcu.cpp totp.cpp sha1.cpp base32.cpp)

target_link_libraries(totp_mcu PUBLIC libace_napi.z.so libc++.a)
target_link_libraries(totp_mcu PUBLIC libhilog_ndk.z.so)