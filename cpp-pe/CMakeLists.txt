
add_executable(cpp-pe main.cpp)

target_include_directories(cpp-pe PRIVATE ${CMAKE_SOURCE_DIR}/beacon)
target_link_libraries(cpp-pe beacon)

if (CMAKE_C_COMPILER_ID MATCHES "MSVC|Clang")
    target_compile_options(cpp-pe PRIVATE /GS- /MT /EHa)
    target_link_options(cpp-pe PRIVATE /MERGE:.gfids=. /MERGE:_RDATA=. /MERGE:.data=. /MERGE:.rdata=. /MERGE:.pdata=. /SECTION:.,RW /MERGE:.discard_data=.discard)

    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        target_link_options(cpp-pe PRIVATE /SAFESEH)
    endif()

else()
    target_link_options(cpp-pe PRIVATE -fexceptions -static -T${LINK_SCRIPT} -Wl,--strip-debug)
endif()
