#===============================================================================
# SE050 Driver — Build settings (scaffold)
#===============================================================================

include_guard(GLOBAL)

set(HF_SE050_TARGET_NAME "hf_se050")

set(HF_SE050_VERSION_MAJOR 0)
set(HF_SE050_VERSION_MINOR 2)
set(HF_SE050_VERSION_PATCH 0)
set(HF_SE050_VERSION "${HF_SE050_VERSION_MAJOR}.${HF_SE050_VERSION_MINOR}.${HF_SE050_VERSION_PATCH}")
set(HF_SE050_VERSION_STRING "${HF_SE050_VERSION}")

set(HF_SE050_VERSION_TEMPLATE "${CMAKE_CURRENT_LIST_DIR}/../inc/se050_version.h.in")
set(HF_SE050_VERSION_HEADER_DIR "${CMAKE_CURRENT_BINARY_DIR}/hf_se050_generated")
set(HF_SE050_VERSION_HEADER     "${HF_SE050_VERSION_HEADER_DIR}/se050_version.h")

file(MAKE_DIRECTORY "${HF_SE050_VERSION_HEADER_DIR}")

if(EXISTS "${HF_SE050_VERSION_TEMPLATE}")
    configure_file(
        "${HF_SE050_VERSION_TEMPLATE}"
        "${HF_SE050_VERSION_HEADER}"
        @ONLY
    )
    message(STATUS "SE050 driver v${HF_SE050_VERSION} — generated se050_version.h in ${HF_SE050_VERSION_HEADER_DIR}")
else()
    message(WARNING "se050_version.h.in not found at ${HF_SE050_VERSION_TEMPLATE}")
endif()

set(HF_SE050_PUBLIC_INCLUDE_DIRS
    "${CMAKE_CURRENT_LIST_DIR}/../inc"
    "${HF_SE050_VERSION_HEADER_DIR}"
)

set(HF_SE050_SOURCE_FILES "")

# ESP-IDF component wrapper (header-only for now)
set(HF_SE050_IDF_REQUIRES driver freertos)
