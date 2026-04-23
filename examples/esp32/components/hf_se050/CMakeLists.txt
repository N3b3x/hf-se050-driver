# hf_se050 — ESP-IDF component wrapper (header-only scaffold)
set(HF_SE050_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../.." CACHE PATH
    "Path to hf-se050-driver root")

get_filename_component(HF_SE050_ROOT "${HF_SE050_ROOT}" ABSOLUTE)
if(NOT EXISTS "${HF_SE050_ROOT}/cmake/hf_se050_build_settings.cmake")
    message(FATAL_ERROR
        "Cannot find SE050 driver root at ${HF_SE050_ROOT}")
endif()

include("${HF_SE050_ROOT}/cmake/hf_se050_build_settings.cmake")

idf_component_register(
    INCLUDE_DIRS ${HF_SE050_PUBLIC_INCLUDE_DIRS}
    REQUIRES ${HF_SE050_IDF_REQUIRES}
)

target_compile_features(${COMPONENT_LIB} INTERFACE cxx_std_17)
