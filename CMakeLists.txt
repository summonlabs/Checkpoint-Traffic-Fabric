cmake_minimum_required(VERSION 3.20)

project(CheckpointTrafficFabric
  VERSION 1.0.0
  DESCRIPTION "Vendor-neutral C++20 runtime for scheduling, isolating, and governing checkpoint network bursts"
  HOMEPAGE_URL "https://github.com/summonlabs/Checkpoint-Traffic-Fabric"
  LANGUAGES CXX)

if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 20)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  set(CTF_IS_TOP_LEVEL ON)
else()
  set(CTF_IS_TOP_LEVEL OFF)
endif()

option(CTF_BUILD_APPS "Build the coordinator, agent, and inspection CLI binaries" ${CTF_IS_TOP_LEVEL})
option(CTF_BUILD_EXAMPLES "Build example programs" ${CTF_IS_TOP_LEVEL})
option(CTF_BUILD_TESTS "Build the test suites" ${CTF_IS_TOP_LEVEL})
option(CTF_BUILD_SHARED "Build the runtime as a shared library" OFF)
option(CTF_WARNINGS_AS_ERRORS "Treat first-party compiler warnings as errors" ON)
option(CTF_ENABLE_ASAN "Enable AddressSanitizer (requires a toolchain shipping the ASan runtime)" OFF)

# ---------------------------------------------------------------------------
# Warning discipline: applied to every first-party target, never suppressed.
# ---------------------------------------------------------------------------
# Applied to first-party targets only, so installed consumers inherit no
# warning policy of ours.
function(ctf_apply_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc)
    if(CTF_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE /WX)
    endif()
  else()
    target_compile_options(${target} PRIVATE
      -Wall -Wextra -Wpedantic -Wshadow -Wnon-virtual-dtor)
    if(CTF_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()
endfunction()

if(CTF_ENABLE_ASAN)
  if(MSVC)
    add_compile_options(/fsanitize=address /Zi)
    add_link_options(/INCREMENTAL:NO)
  else()
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address)
  endif()
endif()

if(CTF_BUILD_SHARED)
  set(CTF_LIBRARY_TYPE SHARED)
else()
  set(CTF_LIBRARY_TYPE STATIC)
endif()

add_library(ctf ${CTF_LIBRARY_TYPE}
  src/bytes.cpp
  src/ids.cpp
  src/status.cpp
  src/hash.cpp
  src/time.cpp
  src/model.cpp
  src/fence.cpp
  src/engine.cpp
  src/shaper.cpp
  src/wire.cpp
  src/store.cpp
  src/net.cpp
  src/protocol.cpp
  src/client.cpp
  src/service.cpp
  src/agent.cpp
  src/config.cpp
  src/report.cpp
  src/version.cpp)
add_library(CheckpointTrafficFabric::ctf ALIAS ctf)

target_include_directories(ctf
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_compile_features(ctf PUBLIC cxx_std_20)
ctf_apply_warnings(ctf)

find_package(Threads REQUIRED)
target_link_libraries(ctf PUBLIC Threads::Threads)
if(WIN32)
  target_link_libraries(ctf PUBLIC ws2_32)
endif()

set_target_properties(ctf PROPERTIES
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  EXPORT_NAME ctf
  POSITION_INDEPENDENT_CODE ON)

# ---------------------------------------------------------------------------
# Install / export rules
# ---------------------------------------------------------------------------
install(TARGETS ctf
  EXPORT CheckpointTrafficFabricTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT CheckpointTrafficFabricTargets
  FILE CheckpointTrafficFabricTargets.cmake
  NAMESPACE CheckpointTrafficFabric::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/CheckpointTrafficFabric)

configure_package_config_file(
  cmake/CheckpointTrafficFabricConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/CheckpointTrafficFabricConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/CheckpointTrafficFabric)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/CheckpointTrafficFabricConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/CheckpointTrafficFabricConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/CheckpointTrafficFabricConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/CheckpointTrafficFabric)

install(FILES README.md LICENSE
  DESTINATION ${CMAKE_INSTALL_DATADIR}/CheckpointTrafficFabric)

# ---------------------------------------------------------------------------
# Apps, examples, tests
# ---------------------------------------------------------------------------
if(CTF_BUILD_APPS)
  add_subdirectory(apps)
endif()

if(CTF_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

if(CTF_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
