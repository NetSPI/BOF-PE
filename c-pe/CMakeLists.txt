
add_executable(c-pe main.cpp)

target_include_directories(c-pe PRIVATE ${CMAKE_SOURCE_DIR}/beacon)
target_link_libraries(c-pe beacon)

if (CMAKE_C_COMPILER_ID MATCHES "MSVC|Clang")
    target_compile_options(c-pe PRIVATE /GS- /MT)
    target_link_options(c-pe PRIVATE /MERGE:.gfids=. /MERGE:_RDATA=. /MERGE:.data=. /MERGE:.rdata=. /MERGE:.pdata=. /SECTION:.,RW /MERGE:.discard_data=.discard)

    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        target_link_options(c-pe PRIVATE /SAFESEH)
    endif()

else()
    target_link_options(c-pe PRIVATE -static)
    target_link_options(c-pe PRIVATE -fno-unwind-tables -fno-asynchronous-unwind-tables -falign-functions=1 -fno-exceptions -fno-rtti -T${LINK_SCRIPT} -Wl,--strip-all)
endif()

