# =============================================================================
# HF-SE050 Driver — ESP-IDF examples (ESP32-S3 scaffold)
# =============================================================================
cmake_minimum_required(VERSION 3.16)

set(DEFAULT_APP_TYPE "se050_minimal_example" CACHE STRING "Default app type for requirements phase")
set(DEFAULT_BUILD_TYPE "Debug" CACHE STRING "Default build type for requirements phase")
set(DEFAULT_SOURCE_FILE "se050_minimal_example.cpp" CACHE STRING "Default source file for requirements phase")

if(NOT DEFINED APP_TYPE)
    message(FATAL_ERROR
        "APP_TYPE not defined. Use build_app.sh from examples/esp32/scripts (git submodule).\n"
        "Example: ./scripts/build_app.sh ${DEFAULT_APP_TYPE} ${DEFAULT_BUILD_TYPE}\n"
        "Or: idf.py with -DAPP_TYPE=... -DBUILD_TYPE=... -DAPP_SOURCE_FILE=..."
    )
endif()

if(NOT DEFINED BUILD_TYPE)
    message(FATAL_ERROR
        "BUILD_TYPE not defined. Use build_app.sh (see README.md)."
    )
endif()

message(STATUS "Building app type: ${APP_TYPE}")
message(STATUS "Build type: ${BUILD_TYPE}")

set(APP_TYPE "${APP_TYPE}" CACHE STRING "App type to build" FORCE)
set(BUILD_TYPE "${BUILD_TYPE}" CACHE STRING "Build type (Debug/Release)" FORCE)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(esp32_se050_${APP_TYPE}_app)
