/** 
  * @file    secboot_aes.h
  * @brief   Secure Boot AES encryption/decryption module for STM32L5 with TrustZone
  * @author  Soulaimane Oulad Belayachi
  * @date    2025-06-05
  * @version 1.0
  * @note    Uses STM32 HAL CRYP for AES-CBC with PKCS7 padding
  * @details This module provides hardware-accelerated AES-CBC with PKCS7 padding
  *          for secure firmware updates on STM32L5 devices.
  */

#ifndef SECBOOT_AES_H
#define SECBOOT_AES_H

#include "stm32l5xx_hal.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>

#define AES_BLOCK_SIZE 16   ///< AES block size in bytes
#define KEY_WORD_SIZE  4    ///< AES-128 key size in 32-bit words
#define IV_WORD_SIZE   4    ///< Initialization vector size in 32-bit words

#define SECBOOT_ORIGIN_ADDR              0x0C000000       ///< Secure boot origin address in flash
#define SECBOOT_AES_KEY_ADDR             (SECBOOT_ORIGIN_ADDR + 0xA040)  ///< Default AES key address (secure zone)
#define SECBOOT_AES_INITVEC_ADDR         (SECBOOT_ORIGIN_ADDR + 0xA050)  ///< Default IV address (secure zone)

/** @brief AES operation status codes */
typedef enum {
    SECBOOT_AES_OK = 0,            ///< Operation successful
    SECBOOT_AES_ERROR,             ///< General error (e.g., HAL failure)
    SECBOOT_AES_INVALID_PARAM,     ///< Invalid input parameters
    SECBOOT_AES_PADDING_ERROR      ///< PKCS7 padding validation failed
} SECBOOT_AES_StatusTypeDef;

/** 
  * @brief AES cryptographic context
  * @warning The key and IV should be stored in secure memory when using TrustZone
  */
typedef struct {
    CRYP_HandleTypeDef hcryp;      ///< STM32 HAL CRYP handle
    uint32_t key[KEY_WORD_SIZE];   ///< AES-128 key (stored in secure memory)
    uint32_t iv[IV_WORD_SIZE];     ///< Initialization vector
} SECBOOT_AES_Context;

/** 
  * @brief AES cryptographic secrets
  * @warning The key and IV should be stored in secure memory when using TrustZone
  */
typedef struct {
    uint32_t key[KEY_WORD_SIZE];   ///< AES-128 key 
    uint32_t iv[IV_WORD_SIZE];     ///< Initialization vector
} SECBOOT_AES_Secrets;

/**
  * @brief  Initialize AES context for CBC mode
  * @param  ctx   Pointer to AES context (must be in secure memory if using TrustZone)
  * @param  key   Pointer to 128-bit key (4x uint32_t)
  * @param  iv    Pointer to initialization vector (4x uint32_t)
  * @retval SECBOOT_AES_StatusTypeDef
  * @note   Uses hardware-accelerated CRYP peripheral
  */
SECBOOT_AES_StatusTypeDef SECBOOT_AES_Init(SECBOOT_AES_Context *ctx, uint32_t *key, uint32_t *iv);



/**
  * @brief  Deinitialize the AES cryptographic context
  * @note   This function:
  *         - Safely deinitializes the AES hardware peripheral
  *         - Clears sensitive data from memory
  *         - Locks the cryptographic module
  *         - Should be called after all crypto operations are complete
  * @param  ctx Pointer to the AES context structure
  * @retval SECBOOT_AES_StatusTypeDef Deinitialization status
  */
SECBOOT_AES_StatusTypeDef SECBOOT_AES_DeInit(SECBOOT_AES_Context *ctx);


/**
  * @brief  Encrypt plaintext using AES-CBC with PKCS7 padding
  * @param  ctx             Pointer to initialized AES context
  * @param  plaintext       Pointer to plaintext data
  * @param  plaintext_len   Length of plaintext in bytes
  * @param  ciphertext      Output buffer for ciphertext (must be 32-bit aligned)
  * @param  ciphertext_len  Output length of ciphertext in words
  * @retval SECBOOT_AES_StatusTypeDef
  * @warning Plaintext buffer must not be in secure memory if called from non-secure zone
  */
SECBOOT_AES_StatusTypeDef SECBOOT_AES_Encrypt(
    SECBOOT_AES_Context *ctx,
    uint8_t *plaintext,
    size_t plaintext_len,
    uint32_t *ciphertext,
    size_t *ciphertext_len
);

/**
  * @brief  Decrypt ciphertext using AES-CBC with PKCS7 padding
  * @param  ctx             Pointer to initialized AES context
  * @param  ciphertext      Pointer to ciphertext data (must be 32-bit aligned)
  * @param  ciphertext_len  Length of ciphertext in words
  * @param  plaintext       Output buffer for plaintext
  * @param  plaintext_len   Output length of plaintext in bytes
  * @retval SECBOOT_AES_StatusTypeDef
  * @note   Automatically validates PKCS7 padding
  */
SECBOOT_AES_StatusTypeDef SECBOOT_AES_Decrypt(
    SECBOOT_AES_Context *ctx,
    uint32_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *plaintext,
    size_t *plaintext_len
);

#endif // SECBOOT_AES_H