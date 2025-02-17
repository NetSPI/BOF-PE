
add_library(beacon SHARED beacon.cpp beacon.h ../common/standalone.cpp ../common/standalone.h)
set_target_properties(beacon PROPERTIES PREFIX "")
set_target_properties(beacon PROPERTIES OUTPUT_NAME beacon)
target_compile_definitions(beacon PRIVATE -DBUILD_BEACON)


if (CMAKE_C_COMPILER_ID STREQUAL "MSVC")
    target_compile_options(beacon PRIVATE /GS- /MT)
else()
    target_link_options(beacon PRIVATE -static)
endif()



