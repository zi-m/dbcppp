cmake_minimum_required(VERSION 3.16 FATAL_ERROR)
project(dbcppp)

option(ENABLE_Ob3 "Enable /Ob3 flag (CMAKE_CXX_FLAGS_DEBUG)" OFF)

if(ENABLE_Ob3)
    string(REGEX REPLACE "/Ob0"  "/Ob3" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
    string(REGEX REPLACE "/Od"   "/O2"  CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
    string(REGEX REPLACE "/RTC1" ""     CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
endif()

find_package(unofficial-libxmlmm CONFIG REQUIRED)
find_package(Boost REQUIRED)

set(dbcppp_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
add_subdirectory(src/libdbcppp)

install(EXPORT dbcppp-config DESTINATION share/dbcppp)
install(DIRECTORY include/dbcppp DESTINATION include)
