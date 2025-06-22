/** 
  * @file    secboot_sha256.c
  * @brief   Implementation of secure boot SHA-256 computation
  * @author  Soulaimane Oulad Belayachi
  * @date    2025-06-05
  * @note    Uses STM32L5 HASH peripheral in blocking mode
  * @details Handles full SHA-256 computation pipeline with error checking
  */

#include "secboot_sha256.h"

static HASH_HandleTypeDef hhash;

/**
  * @brief  Initialize HASH peripheral for SHA-256
  * @retval SECBOOT_SHA_StatusTypeDef
  * @note   Configures the peripheral for 8-bit data input
  */
SECBOOT_SHA_StatusTypeDef SECBOOT_SHA256_Init(void) {


    hhash.Init.DataType = HASH_DATATYPE_8B;

    if (HAL_HASH_Init(&hhash) != HAL_OK) {
        return SECBOOT_SHA256_ERROR_INIT;
    }

    return SECBOOT_SHA256_OK;
}

/**
  * @brief  Compute SHA-256 digest
  * @param[in]  pInput        Input data buffer
  * @param[in]  inputLength   Data length in bytes
  * @param[out] pOutputHash   32-byte output buffer
  * @retval SECBOOT_SHA_StatusTypeDef
  * @note   Implements full pipeline:
  *         1. Input validation
  *         2. Hardware computation (blocking)
  *         3. Digest extraction
  */
SECBOOT_SHA_StatusTypeDef SECBOOT_SHA256_Compute(uint8_t *pInput, uint32_t inputLength, uint8_t *pOutputHash) {
    /* Parameter validation */
    if (pInput == NULL || pOutputHash == NULL) {
        return SECBOOT_SHA256_ERROR_NULL_PTR;
    }
    
    if (inputLength == 0) {
        return SECBOOT_SHA256_ERROR_INVALID_LENGTH;
    }

    /* Compute digest */
    if (HAL_HASHEx_SHA256_Start(&hhash, pInput, inputLength, pOutputHash, HAL_MAX_DELAY) != HAL_OK) {
        return SECBOOT_SHA256_ERROR_COMPUTE;
    }

    /* Finalize computation */
    if (HAL_HASHEx_SHA256_Finish(&hhash, pOutputHash, HAL_MAX_DELAY) != HAL_OK) {
        return SECBOOT_SHA256_ERROR_COMPUTE;
    }

    return SECBOOT_SHA256_OK;
}