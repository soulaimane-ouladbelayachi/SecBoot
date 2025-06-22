/** 
  * @file    secboot_ecdsa.c
  * @brief   STM32L5 PKA-based ECDSA-P256 Signature Verification Implementation
  * @author  Soulaimane Oulad Belayachi
  * @date    2025-06-05
  * @note    Uses HAL_PKA driver with prime256v1 curve parameters
  * @warning All buffers must be in accessible memory regions (secure/non-secure)
  */

#include "secboot_ecdsa.h"

static PKA_HandleTypeDef hpka;  ///< PKA hardware instance handle

/**
  * @brief  Initialize PKA peripheral for ECDSA operations
  * @retval SECBOOT_ECDSA_StatusTypeDef 
  * @note   Implements state tracking to prevent double-init
  */
SECBOOT_ECDSA_StatusTypeDef SECBOOT_ECDSA_Init(void)
{
    static bool is_initialized = false;
    
    /* State check */
    if(is_initialized) {
        return SECBOOT_ECDSA_INVALID_STATE;
    }
    
    /* Hardware initialization */
    hpka.Instance = PKA;
    hpka.State = HAL_PKA_STATE_RESET;
    __HAL_RCC_PKA_CLK_ENABLE();
    
    HAL_StatusTypeDef hal_status = HAL_PKA_Init(&hpka);
    if(hal_status != HAL_OK) {
        __HAL_RCC_PKA_CLK_DISABLE();
        return (hal_status == HAL_TIMEOUT) ? 
               SECBOOT_ECDSA_PKA_TIMEOUT : 
               SECBOOT_ECDSA_PKA_INIT_FAIL;
    }
    
    /* Verify ready state */
    if(HAL_PKA_GetState(&hpka) != HAL_PKA_STATE_READY) {
        HAL_PKA_DeInit(&hpka);
        return SECBOOT_ECDSA_PKA_INIT_FAIL;
    }
    
    is_initialized = true;
    return SECBOOT_ECDSA_OK;
}

/**
  * @brief  Clean up PKA resources
  * @retval SECBOOT_ECDSA_StatusTypeDef
  * @note   Disables PKA clock for power savings
  */
SECBOOT_ECDSA_StatusTypeDef SECBOOT_ECDSA_DeInit(void)
{
    static bool is_initialized = false;
    
    if(!is_initialized) {
        return SECBOOT_ECDSA_INVALID_STATE;
    }
    
    HAL_StatusTypeDef hal_status = HAL_PKA_DeInit(&hpka);
    __HAL_RCC_PKA_CLK_DISABLE();
    
    if(hal_status != HAL_OK) {
        return (hal_status == HAL_TIMEOUT) ? 
               SECBOOT_ECDSA_PKA_TIMEOUT : 
               SECBOOT_ECDSA_ERROR;
    }
    
    is_initialized = false;
    return SECBOOT_ECDSA_OK;
}

/**
  * @brief  Perform ECDSA signature verification
  * @param  pDigest     32-byte SHA-256 hash
  * @param  DigestLen   Must equal SECBOOT_ECDSA_SHA256_DIGEST_SIZE
  * @param  pSignature  Signature to verify
  * @param  pPubKey     Trusted public key
  * @retval SECBOOT_ECDSA_StatusTypeDef
  * @note   Uses PKA hardware for constant-time verification
  */
SECBOOT_ECDSA_StatusTypeDef SECBOOT_ECDSA_Verify_Signature(
    uint8_t* pDigest,
    uint32_t DigestLen,
    SECBOOT_ECC_Signature* pSignature,
    SECBOOT_ECC_PublicKey* pPubKey)
{
    /* Parameter validation */
    if (!pDigest || !pSignature || !pPubKey) {
        return SECBOOT_ECDSA_INVALID_PARAM;
    }

    if (DigestLen != SECBOOT_ECDSA_SHA256_DIGEST_SIZE) {
        return SECBOOT_ECDSA_INVALID_PARAM;
    }

    /* Hardware state check */
    if (HAL_PKA_GetState(&hpka) != HAL_PKA_STATE_READY) {
        return SECBOOT_ECDSA_INVALID_STATE;
    }

    /* Get curve parameters */
    const ECC_Curve_Parameters *curve = get_prime256v1_curve();
    if (!curve) {
        return SECBOOT_ECDSA_ERROR;
    }

    /* Configure PKA operation */
    PKA_ECDSAVerifInTypeDef Sig_verify = {
        .primeOrderSize = curve->order_len,
        .modulusSize = curve->prime_len,
        .coefSign = curve->A_sign,
        .coef = curve->absA,
        .modulus = curve->prime,
        .basePointX = curve->Gx,
        .basePointY = curve->Gy,
        .primeOrder = curve->order,
        .pPubKeyCurvePtX = pPubKey->Qx,
        .pPubKeyCurvePtY = pPubKey->Qy,
        .RSign = pSignature->R,
        .SSign = pSignature->S,
        .hash = pDigest
    };

    /* Execute verification */
    HAL_StatusTypeDef hal_status = HAL_PKA_ECDSAVerif(&hpka, &Sig_verify, 
                                                     SECBOOT_ECDSA_PKA_TIMEOUT_MS);
    if (hal_status != HAL_OK) {
        return (hal_status == HAL_TIMEOUT) ? 
               SECBOOT_ECDSA_PKA_TIMEOUT : 
               SECBOOT_ECDSA_PKA_COMP_ERROR;
    }

    /* Check result */
    return HAL_PKA_ECDSAVerif_IsValidSignature(&hpka) ? 
           SECBOOT_ECDSA_VERIFICATION_SUCCESS : 
           SECBOOT_ECDSA_VERIFICATION_FAIL;
}