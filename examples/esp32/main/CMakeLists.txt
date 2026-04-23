# HF-SE050 ESP32 examples — main component
if(NOT DEFINED APP_TYPE)
    if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
        set(APP_TYPE "${DEFAULT_APP_TYPE}")
        message(STATUS "APP_TYPE default (requirements phase): ${APP_TYPE}")
    else()
        message(FATAL_ERROR "APP_TYPE not defined — use build_app.sh")
    endif()
endif()

if(NOT DEFINED APP_SOURCE_FILE)
    if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
        set(APP_SOURCE_FILE "${DEFAULT_SOURCE_FILE}")
        message(STATUS "APP_SOURCE_FILE default (requirements phase): ${APP_SOURCE_FILE}")
    else()
        message(FATAL_ERROR "APP_SOURCE_FILE not defined — use build_app.sh")
    endif()
endif()

message(STATUS "Building app: ${APP_TYPE}, source: ${APP_SOURCE_FILE}")

set(INC_BASE_PATH "../../../inc")

set(MAIN_INCLUDE_DIRS
    "."
    "${INC_BASE_PATH}"
)

set(MAIN_REQUIRES
    driver
    freertos
    log
    hf_se050
)

idf_component_register(
    SRCS "${APP_SOURCE_FILE}"
    INCLUDE_DIRS ${MAIN_INCLUDE_DIRS}
    REQUIRES ${MAIN_REQUIRES}
)

target_compile_features(${COMPONENT_LIB} PRIVATE cxx_std_17)

if(BUILD_TYPE STREQUAL "Debug")
    target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -O0 -g3 -DDEBUG)
else()
    target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -O2 -g -DNDEBUG)
endif()

target_compile_definitions(${COMPONENT_LIB} PRIVATE "EXAMPLE_TYPE_${APP_TYPE}=1")
