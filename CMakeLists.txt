# =============================================================================
# hf-se050-driver — Root CMakeLists.txt
# =============================================================================
# NXP SE050 / SE050A secure element (I²C). Scaffold: interface library only.
# For ESP-IDF, use the component under examples/esp32/components/hf_se050.
# =============================================================================
cmake_minimum_required(VERSION 3.16)

project(hf_se050
  VERSION 0.1.0
  LANGUAGES CXX
)

include(${CMAKE_CURRENT_LIST_DIR}/cmake/hf_se050_build_settings.cmake)

add_library(${HF_SE050_TARGET_NAME} INTERFACE)
target_include_directories(${HF_SE050_TARGET_NAME} INTERFACE ${HF_SE050_PUBLIC_INCLUDE_DIRS})
target_compile_features(${HF_SE050_TARGET_NAME} INTERFACE cxx_std_17)

add_library(hf::se050 ALIAS ${HF_SE050_TARGET_NAME})

option(HF_SE050_ENABLE_WARNINGS "Enable compiler warnings for SE050 consumers" OFF)
if(HF_SE050_ENABLE_WARNINGS)
  target_compile_options(${HF_SE050_TARGET_NAME} INTERFACE -Wall -Wextra -Wpedantic)
endif()

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/hf_se050ConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/hf_se050Config.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/hf_se050Config.cmake"
  INSTALL_DESTINATION lib/cmake/hf_se050
)
