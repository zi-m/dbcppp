cmake_minimum_required(VERSION 3.16 FATAL_ERROR)
project(libdbcppp)


#
# TestBigEndian
#

include(TestBigEndian)
test_big_endian(is_big_endian)
if (is_big_endian)
    set(BYTE_ORDER Big)
else ()
    set(BYTE_ORDER Little)
endif ()
configure_file(EndianConfig.h.in ${CMAKE_CURRENT_SOURCE_DIR}/EndianConfig.h @ONLY)


#
# libdbcppp
#

message(STATUS "dbcppp_INCLUDE_DIR=${dbcppp_INCLUDE_DIR}")

add_library(libdbcppp SHARED
        "AttributeDefinitionImpl.cpp"
        "AttributeImpl.cpp"
        "BitTimingImpl.cpp"
        "CApi.cpp"
        "DBCAST2Network.cpp"
        "DBCX3.cpp"
        "EnvironmentVariableImpl.cpp"
        "KCD2Network.cpp"
        "MessageImpl.cpp"
        "Network2C.cpp"
        "Network2DBC.cpp"
        "Network2Human.cpp"
        "NetworkImpl.cpp"
        "NodeImpl.cpp"
        "SignalGroupImpl.cpp"
        "SignalImpl.cpp"
        "SignalMultiplexerValueImpl.cpp"
        "SignalTypeImpl.cpp"
        "ValueEncodingDescriptionImpl.cpp"
        "ValueTableImpl.cpp"
        )

target_include_directories(libdbcppp
        PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${dbcppp_INCLUDE_DIR}>
        )

target_link_libraries(libdbcppp
        PRIVATE Boost::headers
        PRIVATE unofficial::libxmlmm::libxmlmm
        )

target_compile_definitions(libdbcppp
        PRIVATE DBCPPP_EXPORT
        )

target_compile_features(libdbcppp
        PUBLIC cxx_std_20
        )

set_target_properties(libdbcppp PROPERTIES
        PREFIX ""
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS NO
        POSITION_INDEPENDENT_CODE ON
        )

install(TARGETS libdbcppp EXPORT dbcppp-config
        RUNTIME DESTINATION bin
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        )
