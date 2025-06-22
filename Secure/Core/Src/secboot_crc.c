/** 
  * @file    secboot_crc.c
  * @brief   Hardware-accelerated CRC32 implementation for STM32L5
  * @author  Soulaimane Oulad Belayachi
  * @date    2025-06-12
  * @version 1.0
  * @note    Uses STM32 hardware CRC peripheral for fast integrity checks
  */

#include "secboot_crc.h"

/* Private variables ---------------------------------------------------------*/

/**
  * @brief  CRC peripheral handle structure
  * @note   Configured for standard CRC-32 calculation
  */
static CRC_HandleTypeDef hcrc;

/* Function implementations --------------------------------------------------*/

/**
  * @brief  Initialize hardware CRC peripheral
  * @retval SECBOOT_CRC_StatusTypeDef Initialization status
  * @note   Configures CRC with these settings:
  *         - Default polynomial (0x04C11DB7)
  *         - Default initial value (0xFFFFFFFF)
  *         - No data inversion
  *         - Byte input format
  */
SECBOOT_CRC_StatusTypeDef SECBOOT_CRC_Init(void)
{
    /* Configure CRC peripheral settings */
    hcrc.Instance = CRC;
    hcrc.Init.DefaultPolynomialUse = DEFAULT_POLYNOMIAL_ENABLE;
    hcrc.Init.DefaultInitValueUse = DEFAULT_INIT_VALUE_ENABLE;
    hcrc.Init.InputDataInversionMode = CRC_INPUTDATA_INVERSION_NONE;
    hcrc.Init.OutputDataInversionMode = CRC_OUTPUTDATA_INVERSION_DISABLE;
    hcrc.InputDataFormat = CRC_INPUTDATA_FORMAT_BYTES;

    /* Initialize CRC peripheral */
    if (HAL_CRC_Init(&hcrc) != HAL_OK) {
        return SECBOOT_CRC_INIT_FAILED;
    }
    
    return SECBOOT_CRC_OK;
}

/**
  * @brief  Compute CRC32 over a memory block
  * @param  pData       Pointer to data buffer
  * @param  dataLength  Length of data in bytes
  * @param  pCrcResult  Pointer to store computed CRC32
  * @retval SECBOOT_CRC_StatusTypeDef Operation status
  * @note   Uses STM32 hardware CRC accelerator
  * @warning Buffer must be accessible (no NULL pointers)
  */
SECBOOT_CRC_StatusTypeDef SECBOOT_CRC_Calculate(
    uint8_t *pData, 
    uint32_t dataLength, 
    uint32_t *pCrcResult
)
{
    /* Parameter validation */
    if (!pData || !pCrcResult) {
        return SECBOOT_CRC_INVALID_PARAM;
    }

    /* Compute CRC using hardware accelerator */
    *pCrcResult = HAL_CRC_Calculate(
        &hcrc, 
        (uint32_t*)pData, 
        dataLength
    );
    
    return SECBOOT_CRC_OK;
}

/**
  * @brief  Verify CRC32 of a memory block
  * @param  pData       Pointer to data buffer
  * @param  dataLength  Length of data in bytes
  * @param  expectedCrc Expected CRC32 value
  * @retval SECBOOT_CRC_StatusTypeDef Verification result
  * @note   Returns SECBOOT_CRC_MISMATCH if computed CRC doesn't match expected value
  */
SECBOOT_CRC_StatusTypeDef SECBOOT_CRC_Verify(
    const uint8_t *pData, 
    uint32_t dataLength, 
    uint32_t expectedCrc
)
{
    uint32_t computedCrc;
    SECBOOT_CRC_StatusTypeDef status;
    
    /* Compute CRC of the data */
    status = SECBOOT_CRC_Calculate((uint8_t*)pData, dataLength, &computedCrc);
    if (status != SECBOOT_CRC_OK) {
        return status;
    }
    
    /* Compare with expected value */
    if (computedCrc != expectedCrc) {
        return SECBOOT_CRC_MISMATCH;
    }
    
    return SECBOOT_CRC_OK;
}

/**
  * @brief  Compute CRC32 incrementally (for large blocks)
  * @param  pData       Pointer to data chunk
  * @param  dataLength  Length of current chunk
  * @param  currentCrc  Current CRC value (updated in-place)
  * @retval SECBOOT_CRC_StatusTypeDef Operation status
  * @note   Initialize *currentCrc with SECBOOT_CRC32_INIT_VALUE
  */
SECBOOT_CRC_StatusTypeDef SECBOOT_CRC_Calculate_Chunk(
    const uint8_t *pData, 
    uint32_t dataLength, 
    uint32_t *currentCrc
)
{
    /* Parameter validation */
    if (!pData || !currentCrc) {
        return SECBOOT_CRC_INVALID_PARAM;
    }

    /* Compute CRC for this chunk */
    *currentCrc = HAL_CRC_Accumulate(
        &hcrc, 
        (uint32_t*)pData, 
        dataLength
    );
    
    return SECBOOT_CRC_OK;
}