cmake_minimum_required(VERSION 3.20)

# Independent downstream consumer: it uses only the installed package, never the
# source tree. Configure with -DCMAKE_PREFIX_PATH=<install prefix>.
project(CtfConsumer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(CheckpointTrafficFabric 1.0.0 REQUIRED CONFIG)

add_executable(ctf_consumer main.cpp)
target_link_libraries(ctf_consumer PRIVATE CheckpointTrafficFabric::ctf)

# Prove the imported target really carries the public headers.
get_target_property(CTF_CONSUMER_INCLUDES CheckpointTrafficFabric::ctf INTERFACE_INCLUDE_DIRECTORIES)
if(NOT CTF_CONSUMER_INCLUDES)
  message(FATAL_ERROR "imported target does not expose include directories")
endif()
