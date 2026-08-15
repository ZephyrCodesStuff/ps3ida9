cmake_minimum_required(VERSION 3.25)

# -------------------------------------------------------------------------
# Support both out-of-tree (pointing to IDASDK) and in-tree builds
# -------------------------------------------------------------------------
if(NOT DEFINED IDASDK AND DEFINED ENV{IDASDK})
    set(IDASDK "$ENV{IDASDK}")
endif()

if(NOT DEFINED IDASDK)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../ida-sdk/src")
        set(IDASDK "${CMAKE_CURRENT_SOURCE_DIR}/../../ida-sdk/src")
    elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../ida-sdk/src")
        set(IDASDK "${CMAKE_CURRENT_SOURCE_DIR}/../ida-sdk/src")
    elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../ida-sdk")
        set(IDASDK "${CMAKE_CURRENT_SOURCE_DIR}/../../ida-sdk")
    elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../ida-sdk")
        set(IDASDK "${CMAKE_CURRENT_SOURCE_DIR}/../ida-sdk")
    endif()
endif()

# Normalize IDASDK to point to directory containing include/ and cmake/
if(EXISTS "${IDASDK}/src/include/pro.h")
    set(IDASDK "${IDASDK}/src")
endif()

set(ENV{IDASDK} "${IDASDK}")

if(EXISTS "${IDASDK}/cmake/idasdk_init.cmake")
    include("${IDASDK}/cmake/idasdk_init.cmake")
elseif(EXISTS "${IDASDK}/src/cmake/idasdk_init.cmake")
    include("${IDASDK}/src/cmake/idasdk_init.cmake")
endif()

project(ps3ida9 CXX)
set(CMAKE_CXX_STANDARD 17)

if(EXISTS "${IDASDK}/cmake")
    list(PREPEND CMAKE_PREFIX_PATH "${IDASDK}/cmake")
elseif(EXISTS "${IDASDK}/src/cmake")
    list(PREPEND CMAKE_PREFIX_PATH "${IDASDK}/src/cmake")
endif()

find_package(idasdk REQUIRED)

ida_add_plugin(ps3ida9
    SOURCES
        ps3ida9.cpp
)
