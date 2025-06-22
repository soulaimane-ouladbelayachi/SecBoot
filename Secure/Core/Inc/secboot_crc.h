/** 
  * @file    secboot_crc.h
  * @brief   Secure Boot CRC Integrity Check Module for STM32L5
  * @author  Soulaimane Oulad Belayachi
  * @date    2025-06-12
  * @version 1.0
  * @note    Uses STM32 hardware CRC peripheral for fast integrity checking
  * @warning Not cryptographically secure - use with other verification methods
  */

#ifndef __SECBOOT_CRC_H
#define __SECBOOT_CRC_H

#include "stm32l5xx_hal.h"
#include <stdint.h>
#include <stdbool.h>

#define SECBOOT_CRC32_INIT_VALUE  0xFFFFFFFFUL  ///< Standard CRC32 initialization value
#define SECBOOT_CRC_POLYNOMIAL    0x04C11DB7UL  ///< Ethernet/PNG standard polynomial

/** @brief CRC status codes */
typedef enum {
    SECBOOT_CRC_OK = 0,            ///< Operation successful
    SECBOOT_CRC_ERROR,             ///< General CRC error
    SECBOOT_CRC_INVALID_PARAM,     ///< Invalid parameters provided
    SECBOOT_CRC_INIT_FAILED,       ///< CRC peripheral initialization failed
    SECBOOT_CRC_MISMATCH           ///< Computed CRC doesn't match expected value
} SECBOOT_CRC_StatusTypeDef;

/**
  * @brief  Initialize hardware CRC peripheral
  * @retval SECBOOT_CRC_StatusTypeDef 
  * @note   Configures CRC with standard polynomial
  * @warning Disables any previously running CRC computation
  */
SECBOOT_CRC_StatusTypeDef SECBOOT_CRC_Init(void);

/**
  * @brief  Compute CRC32 over a memory block
  * @param  pData       Pointer to data buffer
  * @param  dataLength  Length of data in bytes
  * @param  pCrcResult  Pointer to store computed CRC32
  * @retval SECBOOT_CRC_StatusTypeDef
  * @note   Uses STM32 hardware CRC accelerator
  * @warning Data must be word-aligned for optimal performance
  */
SECBOOT_CRC_StatusTypeDef SECBOOT_CRC_Calculate(uint8_t *pData, uint32_t dataLength, uint32_t *pCrcResult);

/**
  * @brief  Verify CRC32 of a memory block
  * @param  pData       Pointer to data buffer
  * @param  dataLength  Length of data in bytes
  * @param  expectedCrc Expected CRC32 value
  * @retval SECBOOT_CRC_StatusTypeDef
  * @note   SECBOOT_CRC_MISMATCH indicates corrupted data
  */
SECBOOT_CRC_StatusTypeDef SECBOOT_CRC_Verify(
    const uint8_t *pData, 
    uint32_t dataLength, 
    uint32_t expectedCrc
);

/**
  * @brief  Compute CRC32 incrementally (for large blocks)
  * @param  pData       Pointer to data chunk
  * @param  dataLength  Length of current chunk
  * @param  currentCrc  Current CRC value (updated in-place)
  * @retval SECBOOT_CRC_StatusTypeDef
  * @note   Initialize *currentCrc with SECBOOT_CRC32_INIT_VALUE
  */
SECBOOT_CRC_StatusTypeDef SECBOOT_CRC_Calculate_Chunk(
    const uint8_t *pData, 
    uint32_t dataLength, 
    uint32_t *currentCrc
);

#endif /* __SECBOOT_CRC_H */