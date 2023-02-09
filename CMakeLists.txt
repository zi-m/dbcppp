cmake_minimum_required(VERSION 3.16 FATAL_ERROR)
project(dbcppp)

find_package(unofficial-libxmlmm CONFIG REQUIRED)
find_package(Boost REQUIRED)

set(dbcppp_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
add_subdirectory(src/libdbcppp)

install(EXPORT dbcppp-config DESTINATION share/dbcppp)
install(DIRECTORY include/dbcppp DESTINATION include)
