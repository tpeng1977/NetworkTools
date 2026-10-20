cmake_minimum_required(VERSION 3.14)
project(VortexShield VERSION 2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

if(MSVC)
  add_compile_options(/W4 /EHsc)
  add_definitions(-D_CRT_SECURE_NO_WARNINGS -D_WIN32_WINNT=0x0601)
else()
  add_compile_options(-Wall -Wextra)
endif()

set(VORTEX_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

function(vortex_link_platform target)
  if(WIN32)
    target_link_libraries(${target} PRIVATE ws2_32)
  else()
    find_package(Threads REQUIRED)
    target_link_libraries(${target} PRIVATE Threads::Threads)
  endif()
endfunction()

add_executable(server src/server.cpp)
target_include_directories(server PRIVATE ${VORTEX_INCLUDE_DIR})
vortex_link_platform(server)

add_executable(client src/client.cpp)
target_include_directories(client PRIVATE ${VORTEX_INCLUDE_DIR})
vortex_link_platform(client)

add_executable(smartlink src/smartlink.cpp)
target_include_directories(smartlink PRIVATE ${VORTEX_INCLUDE_DIR})
vortex_link_platform(smartlink)
if(WIN32)
  target_link_libraries(smartlink PRIVATE iphlpapi)
endif()

add_executable(multilink src/multilink.cpp)
target_include_directories(multilink PRIVATE ${VORTEX_INCLUDE_DIR})
vortex_link_platform(multilink)
if(WIN32)
  target_link_libraries(multilink PRIVATE iphlpapi)
endif()

add_executable(local src/local.cpp)
target_include_directories(local PRIVATE ${VORTEX_INCLUDE_DIR})
vortex_link_platform(local)

if(WIN32)
  add_executable(ap2socks5 src/ap2socks5.cpp)
  target_include_directories(ap2socks5 PRIVATE ${VORTEX_INCLUDE_DIR})
  vortex_link_platform(ap2socks5)
  target_link_libraries(ap2socks5 PRIVATE iphlpapi)
endif()

enable_testing()

add_executable(test_core tests/test_core.cpp)
target_include_directories(test_core PRIVATE ${VORTEX_INCLUDE_DIR})
vortex_link_platform(test_core)
add_test(NAME test_core COMMAND test_core WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

add_executable(test_packet_build tests/test_packet_build.cpp)
target_include_directories(test_packet_build PRIVATE ${VORTEX_INCLUDE_DIR})
add_test(NAME test_packet_build COMMAND test_packet_build WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

add_executable(test_rules tests/test_rules.cpp)
target_include_directories(test_rules PRIVATE ${VORTEX_INCLUDE_DIR})
vortex_link_platform(test_rules)
add_test(NAME test_rules COMMAND test_rules WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

add_executable(test_multilink tests/test_multilink.cpp)
target_include_directories(test_multilink PRIVATE ${VORTEX_INCLUDE_DIR})
vortex_link_platform(test_multilink)
add_test(NAME test_multilink COMMAND test_multilink WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

add_executable(echo_server tests/echo_server.cpp)
target_include_directories(echo_server PRIVATE ${VORTEX_INCLUDE_DIR})
vortex_link_platform(echo_server)

add_executable(socks5_http_get tests/socks5_http_get.cpp)
target_include_directories(socks5_http_get PRIVATE ${VORTEX_INCLUDE_DIR})
vortex_link_platform(socks5_http_get)

add_executable(probe_test tests/probe_test.cpp)
target_include_directories(probe_test PRIVATE ${VORTEX_INCLUDE_DIR})
vortex_link_platform(probe_test)

add_executable(wrong_secret_test tests/wrong_secret_test.cpp)
target_include_directories(wrong_secret_test PRIVATE ${VORTEX_INCLUDE_DIR})
vortex_link_platform(wrong_secret_test)

add_executable(binary_echo_test tests/binary_echo_test.cpp)
target_include_directories(binary_echo_test PRIVATE ${VORTEX_INCLUDE_DIR})
vortex_link_platform(binary_echo_test)

add_executable(stress_test tests/stress_test.cpp)
target_include_directories(stress_test PRIVATE ${VORTEX_INCLUDE_DIR})
vortex_link_platform(stress_test)

install(TARGETS server client smartlink multilink local RUNTIME DESTINATION bin)
install(DIRECTORY config/ DESTINATION share/vortex-shield/config)

message(STATUS "Vortex Shield ${PROJECT_VERSION} (${CMAKE_SYSTEM_NAME})")
