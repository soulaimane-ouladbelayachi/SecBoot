/** 
  * @file    secboot_sha256.h
  * @brief   Secure Boot SHA-256 hardware accelerator module for STM32L5
  * @author  Soulaimane Oulad Belayachi
  * @date    2025-06-05
  * @version 1.0
  * @note    Uses STM32L5 HASH peripheral for SHA-256 computation
  * @warning Input buffers must be in non-secure memory if called from non-secure zone
  */

#ifndef __SECBOOT_SHA256_H
#define __SECBOOT_SHA256_H

#include <stdint.h>
#include "stm32l5xx.h"

/** @brief SHA-256 operation status codes */
typedef enum {
    SECBOOT_SHA256_OK = 0x00,         ///< Operation completed successfully
    SECBOOT_SHA256_ERROR_INIT,              ///< HASH peripheral initialization failed
    SECBOOT_SHA256_ERROR_COMPUTE,           ///< Digest computation failed
    SECBOOT_SHA256_ERROR_NULL_PTR,          ///< NULL pointer encountered
    SECBOOT_SHA256_ERROR_INVALID_LENGTH,    ///< Input length is zero or invalid
    SECBOOT_SHA256_ERROR_TIMEOUT            ///< Hardware operation timeout
} SECBOOT_SHA_StatusTypeDef;

/**
  * @brief  Initialize the SHA-256 hardware accelerator
  * @retval SECBOOT_SHA_StatusTypeDef 
  * @note   Configures HASH peripheral for 8-bit data input
  * @warning Must be called before any SHA256_Compute operation
  */
SECBOOT_SHA_StatusTypeDef SECBOOT_SHA256_Init(void);

/**
  * @brief  Compute SHA-256 digest of input data
  * @param[in]  pInput        Pointer to input data buffer (8-bit aligned)
  * @param[in]  inputLength   Length of input data in bytes (max 2^32-1)
  * @param[out] pOutputHash   Pointer to output buffer (32 bytes minimum)
  * @retval SECBOOT_SHA_StatusTypeDef
  * @note   Uses blocking mode with HAL_MAX_DELAY
  * @warning Output buffer must be 32-bit aligned for optimal performance
  */
SECBOOT_SHA_StatusTypeDef SECBOOT_SHA256_Compute(uint8_t *pInput, uint32_t inputLength, uint8_t *pOutputHash);

#endif 
/* __SECBOOT_SHA256_H */