
add_executable(loader main.cpp ../common/standalone.cpp ../common/standalone.h)
target_compile_features(loader PRIVATE cxx_std_20)
target_include_directories(loader PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

if (NOT CMAKE_C_COMPILER_ID STREQUAL "MSVC")
    target_link_options(loader PRIVATE -static)
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_link_libraries(loader ${CMAKE_SOURCE_DIR}/ntdll_x64.lib)
else()
    target_link_libraries(loader ${CMAKE_SOURCE_DIR}/ntdll_x86.lib)
endif()
