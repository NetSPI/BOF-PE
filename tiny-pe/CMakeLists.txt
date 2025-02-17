
add_executable(tiny-pe main.cpp)

target_include_directories(tiny-pe PRIVATE ${CMAKE_SOURCE_DIR}/beacon)
target_link_libraries(tiny-pe beacon)

if (CMAKE_C_COMPILER_ID MATCHES "MSVC|Clang")
    STRING (REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    STRING (REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
    STRING (REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
    STRING (REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")    
    target_compile_options(tiny-pe PRIVATE /GS- /MT)
    target_link_options(tiny-pe PRIVATE /ENTRY:entry /NODEFAULTLIB /MERGE:.data=. /MERGE:.rdata=. /MERGE:.pdata=. /SECTION:.,RW /GUARD:NO)
else()
    target_link_options(tiny-pe PRIVATE -nostdlib -eentry -fno-unwind-tables -fno-asynchronous-unwind-tables -falign-functions=1 -fno-exceptions -fno-rtti -T${LINK_SCRIPT} -Wl,--strip-all)
endif()
