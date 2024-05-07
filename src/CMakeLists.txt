file(GLOB_RECURSE sources CONFIGURE_DEPENDS "*.cpp")

add_library(pqc STATIC ${sources})
add_library(pqc_shared SHARED ${sources})

target_include_directories(pqc
    PRIVATE "${PROJECT_SOURCE_DIR}/include" "${PROJECT_SOURCE_DIR}/src"
    INTERFACE "${PROJECT_SOURCE_DIR}/include"
)

target_include_directories(pqc_shared
    PRIVATE "${PROJECT_SOURCE_DIR}/include" "${PROJECT_SOURCE_DIR}/src"
    INTERFACE "${PROJECT_SOURCE_DIR}/include"
)

set(DEFINES "")
if(HASWELL)
    set(DEFINES "${DEFINES};__AVX__;__AVX2__")
endif()
include(TestBigEndian)
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
if(IS_BIG_ENDIAN)
    set(DEFINES "${DEFINES};__BIG_ENDIAN__")
endif()

target_compile_definitions(pqc PRIVATE "${DEFINES}")
target_compile_definitions(pqc_shared PRIVATE "PQC_EXPORTS;${DEFINES}" PUBLIC "PQC_SHARED")
