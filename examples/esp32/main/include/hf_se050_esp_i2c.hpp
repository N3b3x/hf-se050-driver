/**
 * @file hf_se050_esp_i2c.hpp
 * @brief ESP-IDF v5.5+ I2C master transport for `se050::Device<>` (CRTP).
 * @copyright Copyright (c) 2026 HardFOC. All rights reserved.
 */
#pragma once

#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "se050_i2c_transport_interface.hpp"
#include "se050_types.hpp"

#include <climits>
#include <cstring>

namespace hf_se050_examples {

/** Wiring and bus parameters for the minimal example (override before construction). */
struct Se050EspI2cConfig {
    i2c_port_t port{I2C_NUM_0};
    gpio_num_t sda{GPIO_NUM_47};
    gpio_num_t scl{GPIO_NUM_48};
    std::uint32_t freq_hz{100'000};
    /** 7-bit address (default SE050). */
    std::uint8_t device_address7{se050::kDefaultI2cAddress7};
    /** Optional SE_RESET; `GPIO_NUM_NC` if not connected. */
    gpio_num_t reset_gpio{GPIO_NUM_NC};
};

/**
 * @brief CRTP transport: one I2C device @ `device_address7`, fixed SDA/SCL.
 */
class HfSe050EspIdfI2c : public se050::I2cTransceiveInterface<HfSe050EspIdfI2c> {
public:
    explicit HfSe050EspIdfI2c(const Se050EspI2cConfig& cfg = Se050EspI2cConfig{}) noexcept
        : cfg_(cfg), bus_(nullptr), dev_(nullptr), inited_(false) {}

    HfSe050EspIdfI2c(const HfSe050EspIdfI2c&) = delete;
    HfSe050EspIdfI2c& operator=(const HfSe050EspIdfI2c&) = delete;

    ~HfSe050EspIdfI2c() noexcept { Shutdown(); }

    [[nodiscard]] bool EnsureInitialized() noexcept {
        if (inited_) {
            return true;
        }
        i2c_master_bus_config_t bus_cfg{};
        bus_cfg.i2c_port = cfg_.port;
        bus_cfg.sda_io_num = cfg_.sda;
        bus_cfg.scl_io_num = cfg_.scl;
        bus_cfg.clk_source = I2C_CLK_SRC_DEFAULT;
        bus_cfg.glitch_ignore_cnt = 7;
        bus_cfg.intr_priority = 0;
        bus_cfg.trans_queue_depth = 0;
        bus_cfg.flags.enable_internal_pullup = 1;

        if (i2c_new_master_bus(&bus_cfg, &bus_) != ESP_OK) {
            ESP_LOGE(tag_, "i2c_new_master_bus failed");
            return false;
        }

        i2c_device_config_t dev_cfg{};
        dev_cfg.dev_addr_length = I2C_ADDR_BIT_LEN_7;
        dev_cfg.device_address = cfg_.device_address7;
        dev_cfg.scl_speed_hz = cfg_.freq_hz;
        dev_cfg.scl_wait_us = 0;
        dev_cfg.flags.disable_ack_check = 0;

        if (i2c_master_bus_add_device(bus_, &dev_cfg, &dev_) != ESP_OK) {
            ESP_LOGE(tag_, "i2c_master_bus_add_device failed");
            (void)i2c_del_master_bus(bus_);
            bus_ = nullptr;
            return false;
        }

        if (cfg_.reset_gpio != GPIO_NUM_NC) {
            gpio_config_t io{};
            io.pin_bit_mask = (1ULL << static_cast<unsigned>(cfg_.reset_gpio));
            io.mode = GPIO_MODE_OUTPUT;
            io.pull_up_en = GPIO_PULLUP_DISABLE;
            io.pull_down_en = GPIO_PULLDOWN_DISABLE;
            io.intr_type = GPIO_INTR_DISABLE;
            if (gpio_config(&io) != ESP_OK) {
                ESP_LOGE(tag_, "gpio_config reset pin failed");
                (void)i2c_master_bus_rm_device(dev_);
                dev_ = nullptr;
                (void)i2c_del_master_bus(bus_);
                bus_ = nullptr;
                return false;
            }
            gpio_set_level(cfg_.reset_gpio, 1);
        }

        inited_ = true;
        ESP_LOGI(tag_, "I2C bus OK (port=%d SDA=%d SCL=%d addr=0x%02x %ukHz)", static_cast<int>(cfg_.port),
                 static_cast<int>(cfg_.sda), static_cast<int>(cfg_.scl), static_cast<unsigned>(cfg_.device_address7),
                 static_cast<unsigned>(cfg_.freq_hz / 1000U));
        return true;
    }

    void Shutdown() noexcept {
        if (dev_ != nullptr) {
            (void)i2c_master_bus_rm_device(dev_);
            dev_ = nullptr;
        }
        if (bus_ != nullptr) {
            (void)i2c_del_master_bus(bus_);
            bus_ = nullptr;
        }
        inited_ = false;
    }

    [[nodiscard]] se050::Error I2cWrite(const std::uint8_t* tx, std::size_t tx_len,
                                        std::uint32_t timeout_ms) noexcept {
        if (tx == nullptr || tx_len == 0U) {
            return se050::Error::InvalidArgument;
        }
        if (!EnsureInitialized()) {
            return se050::Error::NotInitialized;
        }
        const int xfer_timeout =
            (timeout_ms > static_cast<std::uint32_t>(INT_MAX)) ? INT_MAX : static_cast<int>(timeout_ms);
        const esp_err_t err = i2c_master_transmit(dev_, tx, tx_len, xfer_timeout);
        if (err != ESP_OK) {
            ESP_LOGW(tag_, "I2C write err=%s", esp_err_to_name(err));
            return se050::Error::Transport;
        }
        return se050::Error::Ok;
    }

    [[nodiscard]] se050::Error I2cRead(std::uint8_t* rx, std::size_t rx_len, std::uint32_t timeout_ms) noexcept {
        if (rx == nullptr || rx_len == 0U) {
            return se050::Error::InvalidArgument;
        }
        if (!EnsureInitialized()) {
            return se050::Error::NotInitialized;
        }
        std::memset(rx, 0, rx_len);
        const int xfer_timeout =
            (timeout_ms > static_cast<std::uint32_t>(INT_MAX)) ? INT_MAX : static_cast<int>(timeout_ms);
        const esp_err_t err = i2c_master_receive(dev_, rx, rx_len, xfer_timeout);
        if (err != ESP_OK) {
            ESP_LOGW(tag_, "I2C read err=%s", esp_err_to_name(err));
            return se050::Error::Transport;
        }
        return se050::Error::Ok;
    }

    [[nodiscard]] se050::Error Transceive(const std::uint8_t* tx, std::size_t tx_len, std::uint8_t* rx,
                                          std::size_t rx_cap, std::size_t* rx_len_out,
                                          std::uint32_t timeout_ms) noexcept {
        if (rx_len_out == nullptr) {
            return se050::Error::InvalidArgument;
        }
        *rx_len_out = 0;
        if (tx_len == 0U) {
            return se050::Error::InvalidArgument;
        }
        if (!EnsureInitialized()) {
            return se050::Error::NotInitialized;
        }
        const int xfer_timeout =
            (timeout_ms > static_cast<std::uint32_t>(INT_MAX)) ? INT_MAX : static_cast<int>(timeout_ms);

        if (rx_cap == 0U || rx == nullptr) {
            const esp_err_t err = i2c_master_transmit(dev_, tx, tx_len, xfer_timeout);
            if (err != ESP_OK) {
                ESP_LOGW(tag_, "I2C transmit err=%s", esp_err_to_name(err));
                return se050::Error::Transport;
            }
            return se050::Error::Ok;
        }

        const se050::Error w = I2cWrite(tx, tx_len, timeout_ms);
        if (w != se050::Error::Ok) {
            return w;
        }
        delay_ms_impl(2);
        const se050::Error r = I2cRead(rx, rx_cap, timeout_ms);
        if (r == se050::Error::Ok) {
            *rx_len_out = rx_cap;
        }
        return r;
    }

    void delay_ms_impl(std::uint32_t ms) noexcept { vTaskDelay(pdMS_TO_TICKS(ms)); }

    [[nodiscard]] se050::Error HardwareReset() noexcept {
        if (cfg_.reset_gpio == GPIO_NUM_NC) {
            return se050::Error::Ok;
        }
        if (!EnsureInitialized()) {
            return se050::Error::NotInitialized;
        }
        gpio_set_level(cfg_.reset_gpio, 0);
        delay_ms_impl(2);
        gpio_set_level(cfg_.reset_gpio, 1);
        delay_ms_impl(10);
        return se050::Error::Ok;
    }

private:
    static constexpr const char* tag_{"hf_se050_i2c"};
    Se050EspI2cConfig cfg_{};
    i2c_master_bus_handle_t bus_;
    i2c_master_dev_handle_t dev_;
    bool inited_;
};

}  // namespace hf_se050_examples
