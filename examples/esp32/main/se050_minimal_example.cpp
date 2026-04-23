/**
 * @file se050_minimal_example.cpp
 * @brief Scaffold — verifies include path and logging; SE050 I2C TBD.
 */
#include "esp_log.h"
#include "se050_driver.hpp"

static const char* TAG = "se050_minimal";

extern "C" void app_main(void)
{
    ESP_LOGI(TAG, "HF-SE050 scaffold — driver API TBD");
    (void)sizeof(hf::se050::Driver);
}
