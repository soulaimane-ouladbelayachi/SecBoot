/** 
  * @file    secboot_aes.c
  * @brief   Implementation of secure boot AES-CBC with PKCS7 padding
  * @author  Soulaimane Oulad Belayachi
  * @date    2025-06-05
  * @note    Uses STM32L5 hardware crypto accelerator (CRYP)
  * @details Handles endianness conversion and padding for STM32 HAL CRYP peripheral.
  */

#include "secboot_aes.h"

/** @brief PKCS7 padding status codes (internal use) */
typedef enum {
    PKCS7_PAD_OK = 0,      ///< Padding applied successfully
    PKCS7_PAD_NOK,         ///< Padding failed
    PKCS7_UNPAD_OK,        ///< Unpadding successful
    PKCS7_UNPAD_NOK        ///< Unpadding failed
} PKCS7_Status;

/* Private function prototypes */
static PKCS7_Status PKCS7_Pad(const uint8_t *input, size_t len, uint8_t *output, size_t *out_len);
static PKCS7_Status PKCS7_Unpad(uint8_t *input, size_t input_len, uint8_t *output, size_t *output_len);
static void bytes_to_uint32_be(uint8_t *input, size_t input_len, uint32_t *output);
static void uint32_to_bytes_be(uint32_t *input, size_t word_count, uint8_t *output);

/**
  * @brief  Apply PKCS7 padding to input data
  * @param  input      Pointer to input data
  * @param  len        Length of input data in bytes
  * @param  output     Output buffer (must have space for padding)
  * @param  out_len    Resulting length after padding
  * @retval PKCS7_Status
  * @note   Output buffer must be at least (len + (AES_BLOCK_SIZE - (len % AES_BLOCK_SIZE))) bytes
  */
static PKCS7_Status PKCS7_Pad(const uint8_t *input, size_t len, uint8_t *output, size_t *out_len) {
    uint8_t pad_len = AES_BLOCK_SIZE - (len % AES_BLOCK_SIZE);
    memcpy(output, input, len);
    
    for (uint8_t i = 0; i < pad_len; i++) {
        output[len + i] = pad_len;
    }
    
    *out_len = len + pad_len;
    return PKCS7_PAD_OK;
}

/**
  * @brief  Remove PKCS7 padding from input data
  * @param  input       Pointer to padded input data
  * @param  input_len   Length of input data in bytes (must be AES_BLOCK_SIZE aligned)
  * @param  output      Output buffer for unpadded data
  * @param  output_len  Length of unpadded data
  * @retval PKCS7_Status
  * @warning Returns PKCS7_UNPAD_NOK if padding is invalid (potential attack)
  */
static PKCS7_Status PKCS7_Unpad(uint8_t *input, size_t input_len, uint8_t *output, size_t *output_len) {
    if (!input || !output || !output_len) return PKCS7_UNPAD_NOK;
    if (input_len == 0 || input_len % AES_BLOCK_SIZE != 0) return PKCS7_UNPAD_NOK;

    uint8_t pad = input[input_len - 1];
    if (pad == 0 || pad > AES_BLOCK_SIZE || pad > input_len) return PKCS7_UNPAD_NOK;

    /* Validate all padding bytes */
    for (size_t i = 0; i < pad; i++) {
        if (input[input_len - 1 - i] != pad) return PKCS7_UNPAD_NOK;
    }

    *output_len = input_len - pad;
    memcpy(output, input, *output_len);
    return PKCS7_UNPAD_OK;
}

/**
  * @brief  Convert byte array to big-endian 32-bit words
  * @param  input      Input byte array (little-endian)
  * @param  input_len  Length of input in bytes (must be multiple of 4)
  * @param  output     Output word array (big-endian)
  */
static void bytes_to_uint32_be(uint8_t *input, size_t input_len, uint32_t *output) {
    for (size_t i = 0; i < input_len / 4; i++) {
        output[i] = ((uint32_t)input[4*i + 0] << 24) |
                    ((uint32_t)input[4*i + 1] << 16) |
                    ((uint32_t)input[4*i + 2] << 8)  |
                    ((uint32_t)input[4*i + 3]);
    }
}

/**
  * @brief  Convert 32-bit words to big-endian byte array
  * @param  input       Input word array (big-endian)
  * @param  word_count  Number of 32-bit words
  * @param  output      Output byte array (little-endian)
  */
static void uint32_to_bytes_be(uint32_t *input, size_t word_count, uint8_t *output) {
    for (size_t i = 0; i < word_count; i++) {
        output[4*i + 0] = (uint8_t)(input[i] >> 24);
        output[4*i + 1] = (uint8_t)(input[i] >> 16);
        output[4*i + 2] = (uint8_t)(input[i] >> 8);
        output[4*i + 3] = (uint8_t)(input[i]);
    }
}

SECBOOT_AES_StatusTypeDef SECBOOT_AES_Init(SECBOOT_AES_Context *ctx, uint32_t *key, uint32_t *iv) {
    if (!ctx || !key || !iv) return SECBOOT_AES_INVALID_PARAM;

    memcpy(ctx->iv, iv, IV_WORD_SIZE * sizeof(uint32_t));
    memcpy(ctx->key, key, KEY_WORD_SIZE * sizeof(uint32_t));

    ctx->hcryp.Instance = AES;
    ctx->hcryp.Init.DataType = CRYP_DATATYPE_32B;
    ctx->hcryp.Init.KeySize = CRYP_KEYSIZE_128B;
    ctx->hcryp.Init.pKey = (uint32_t *)ctx->key;
    ctx->hcryp.Init.pInitVect = (uint32_t *)ctx->iv;
    ctx->hcryp.Init.Algorithm = CRYP_AES_CBC;
    ctx->hcryp.Init.DataWidthUnit = CRYP_DATAWIDTHUNIT_WORD;
    ctx->hcryp.Init.KeyIVConfigSkip = CRYP_KEYIVCONFIG_ALWAYS;

    if (HAL_CRYP_Init(&ctx->hcryp) != HAL_OK) {
        return SECBOOT_AES_ERROR;
    }    

    return SECBOOT_AES_OK;
}

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
SECBOOT_AES_StatusTypeDef SECBOOT_AES_DeInit(SECBOOT_AES_Context *ctx)
{
    /* 1. Parameter Validation */
    if (!ctx) {
        return SECBOOT_AES_INVALID_PARAM;
    }

    /* 2. Hardware Deinitialization */
    if (HAL_CRYP_DeInit(&ctx->hcryp) != HAL_OK) {
        return SECBOOT_AES_ERROR;
    }

    /* 3. Secure Data Cleansing */
    volatile uint32_t *pKey = (volatile uint32_t *)ctx->key;
    volatile uint32_t *pIV = (volatile uint32_t *)ctx->iv;
    
    for (int i = 0; i < KEY_WORD_SIZE; i++) {
        pKey[i] = 0x00000000;
    }
    
    for (int i = 0; i < IV_WORD_SIZE; i++) {
        pIV[i] = 0x00000000;
    }

    /* 5. Context Structure Sanitization */
    memset(ctx, 0, sizeof(SECBOOT_AES_Context));

    return SECBOOT_AES_OK;
}


SECBOOT_AES_StatusTypeDef SECBOOT_AES_Encrypt(
    SECBOOT_AES_Context *ctx,
    uint8_t *plaintext,
    size_t plaintext_len,
    uint32_t *ciphertext,
    size_t *ciphertext_len
) {
    if (!ctx || !plaintext || !ciphertext || !ciphertext_len) {
        return SECBOOT_AES_INVALID_PARAM;
    }

    size_t padding_size_bytes = plaintext_len + AES_BLOCK_SIZE - (plaintext_len % AES_BLOCK_SIZE);
    size_t padding_size_words = padding_size_bytes / 4;
    uint8_t padded_bytes_input[padding_size_bytes];
    uint32_t padded_words_input[padding_size_words];
    uint32_t cipher_output[padding_size_words];

    size_t padded_bytes_len = 0;
    size_t padded_words_len = 0;
    
    if (PKCS7_Pad(plaintext, plaintext_len, padded_bytes_input, &padded_bytes_len) != PKCS7_PAD_OK) {
        return SECBOOT_AES_PADDING_ERROR;
    }

    padded_words_len = padded_bytes_len / 4;
    bytes_to_uint32_be(padded_bytes_input, padded_bytes_len, padded_words_input);

    if (HAL_CRYP_Encrypt(&ctx->hcryp, padded_words_input, (uint16_t)padded_words_len, 
                         cipher_output, HAL_MAX_DELAY) != HAL_OK) {
        return SECBOOT_AES_ERROR;
    }

    memcpy(ciphertext, cipher_output, padded_words_len * sizeof(uint32_t));
    *ciphertext_len = padded_words_len;
    return SECBOOT_AES_OK;
}

SECBOOT_AES_StatusTypeDef SECBOOT_AES_Decrypt(
    SECBOOT_AES_Context *ctx,
    uint32_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *plaintext,
    size_t *plaintext_len
) {
    size_t plaintextPadded_words_len = ciphertext_len;
    size_t plaintextPadded_bytes_len = ciphertext_len * 4;
    uint32_t plaintextPadded_words[plaintextPadded_words_len];
    uint8_t plaintextPadded_bytes[plaintextPadded_bytes_len];
    uint8_t plaintextUnpadded_bytes[plaintextPadded_bytes_len];
    size_t plaintextUnpadded_bytes_len = 0;

    if (HAL_CRYP_Decrypt(&ctx->hcryp, ciphertext, ciphertext_len,
                         plaintextPadded_words, HAL_MAX_DELAY) != HAL_OK) {
        return SECBOOT_AES_ERROR;
    }

    uint32_to_bytes_be(plaintextPadded_words, plaintextPadded_words_len, plaintextPadded_bytes);

    if (PKCS7_Unpad(plaintextPadded_bytes, plaintextPadded_bytes_len,
                    plaintextUnpadded_bytes, &plaintextUnpadded_bytes_len) != PKCS7_UNPAD_OK) {
        return SECBOOT_AES_PADDING_ERROR;
    }

    memcpy(plaintext, plaintextUnpadded_bytes, plaintextUnpadded_bytes_len);
    *plaintext_len = plaintextUnpadded_bytes_len;
    return SECBOOT_AES_OK;
}


