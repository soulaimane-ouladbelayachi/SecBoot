/** 
  * @file    secboot_ecdsa.h
  * @brief   Secure Boot ECDSA-P256 Signature Verification Module for STM32L5
  * @author  Soulaimane Oulad Belayachi
  * @date    2025-06-05
  * @version 1.0
  * @note    Uses STM32L5 PKA hardware accelerator for NIST P-256 curve
  * @warning All keys and signatures must be in big-endian format
  */

#ifndef SECBOOT_ECDSA_H
#define SECBOOT_ECDSA_H

#include "stdint.h"
#include "stm32l5xx.h"
#include <stdbool.h>
#include "prime256v1.h"

#define ECC_PUBKEY_QX_SIZE       32  ///< Public key X-coordinate size in bytes (P-256)
#define ECC_PUBKEY_QY_SIZE       32  ///< Public key Y-coordinate size in bytes (P-256)
#define ECC_SIGNATURE_R_SIZE     32  ///< Signature R component size in bytes
#define ECC_SIGNATURE_S_SIZE     32  ///< Signature S component size in bytes

#define SECBOOT_ECDSA_SHA256_DIGEST_SIZE 32  ///< Required digest size for P-256
#define SECBOOT_ECDSA_PKA_TIMEOUT_MS 1000    ///< PKA operation timeout in ms

#define SECBOOT_ORIGIN_ADDR        0x0C000000      ///< Secure boot base address
#define SECBOOT_PUBKEY_QX_ADDR     (SECBOOT_ORIGIN_ADDR + 0xA000)  ///< Default public key X address
#define SECBOOT_PUBKEY_QY_ADDR     (SECBOOT_ORIGIN_ADDR + 0xA020)  ///< Default public key Y address

/**
  * @brief  ECDSA operation status codes
  * @note   Detailed error codes for secure boot diagnostics
  */
typedef enum {
  SECBOOT_ECDSA_OK = 0,                 ///< Operation successful
  SECBOOT_ECDSA_ERROR = 1,              ///< Generic error
  
  /* Parameter/State Errors */
  SECBOOT_ECDSA_INVALID_PARAM = 2,      ///< NULL pointer or invalid size
  SECBOOT_ECDSA_INVALID_STATE = 3,      ///< Invalid module state
  
  /* Hardware Errors */
  SECBOOT_ECDSA_PKA_INIT_FAIL = 4,      ///< PKA peripheral init failed
  SECBOOT_ECDSA_PKA_COMP_ERROR = 5,     ///< PKA computation error
  SECBOOT_ECDSA_PKA_TIMEOUT = 6,        ///< PKA operation timeout
  
  /* Verification Results */
  SECBOOT_ECDSA_VERIFICATION_SUCCESS = 7, ///< Signature valid (matches SECBOOT_ECDSA_OK)
  SECBOOT_ECDSA_VERIFICATION_FAIL = 8,  ///< Signature invalid (security critical)
  
  /* Data Format Errors */
  SECBOOT_ECDSA_INVALID_SIGNATURE = 9,  ///< Malformed signature
  SECBOOT_ECDSA_INVALID_PUBKEY = 10     ///< Invalid public key format
} SECBOOT_ECDSA_StatusTypeDef;

/**
  * @brief  ECC Public Key Structure (P-256)
  * @note   Uses uncompressed format with X/Y coordinates
  */
typedef struct {
  uint8_t Qx[ECC_PUBKEY_QX_SIZE];  ///< X-coordinate (big-endian)
  uint8_t Qy[ECC_PUBKEY_QY_SIZE];  ///< Y-coordinate (big-endian)
} SECBOOT_ECC_PublicKey;

/**
  * @brief  ECDSA Signature Structure (P-256)
  */
typedef struct {
  uint8_t R[ECC_SIGNATURE_R_SIZE];  ///< Signature R component (big-endian)
  uint8_t S[ECC_SIGNATURE_S_SIZE];  ///< Signature S component (big-endian)
} SECBOOT_ECC_Signature;

/* --- Function Prototypes --- */

/**
  * @brief  Initialize PKA peripheral for ECDSA operations
  * @retval SECBOOT_ECDSA_StatusTypeDef 
  * @note   Must be called before signature verification
  * @warning Enables PKA clock - ensure power management is configured
  */
SECBOOT_ECDSA_StatusTypeDef SECBOOT_ECDSA_Init(void);

/**
  * @brief  Deinitialize PKA peripheral
  * @retval SECBOOT_ECDSA_StatusTypeDef
  * @note   Disables PKA clock to save power
  */
SECBOOT_ECDSA_StatusTypeDef SECBOOT_ECDSA_DeInit(void);

/**
  * @brief  Verify ECDSA signature of a firmware digest
  * @param  pDigest      Pointer to SHA-256 hash (32 bytes)
  * @param  DigestLen    Must be SECBOOT_ECDSA_SHA256_DIGEST_SIZE
  * @param  pSignature   ECDSA signature to verify
  * @param  pPubKey      Trusted public key
  * @retval SECBOOT_ECDSA_StatusTypeDef
  * @warning SECBOOT_ECDSA_VERIFICATION_FAIL indicates compromised firmware
  */
SECBOOT_ECDSA_StatusTypeDef SECBOOT_ECDSA_Verify_Signature(
    uint8_t* pDigest,
    uint32_t DigestLen,
    SECBOOT_ECC_Signature* pSignature,
    SECBOOT_ECC_PublicKey* pPubKey);

#endif /* SECBOOT_ECDSA_H */