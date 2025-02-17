cmake_minimum_required(VERSION 3.18)
project(bof-pe )

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

message("-- Building for ${CMAKE_CXX_COMPILER_ID} compiler")

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(LINK_SCRIPT ${CMAKE_SOURCE_DIR}/link.ld)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(LINK_SCRIPT ${CMAKE_SOURCE_DIR}/link32.ld)
endif()

include_directories(${CMAKE_SOURCE_DIR}/beacon/)

add_subdirectory(beacon)
add_subdirectory(loader)
add_subdirectory(tiny-pe)
add_subdirectory(c-pe)
add_subdirectory(cpp-pe)

install(TARGETS beacon loader tiny-pe c-pe cpp-pe DESTINATION "")
