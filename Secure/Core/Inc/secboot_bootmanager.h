/**
  * @file    SECBOOT_BootManager.h
  * @brief   Secure Bootloader Manager for STM32L5 with Cortex-M33 TrustZone
  * @version 1.0.0
  * @date    2025-06-13
  * @author  Soulaimane Oulad Belayachi
  *
  * 
  * @details
  * This header defines the interface for the secure bootloader manager that provides:
  * - Secure firmware verification
  * - TrustZone configuration
  * - Cryptographic operations
  * - Secure boot sequence control
  */

#ifndef SECBOOT_BOOTMANAGER_H
#define SECBOOT_BOOTMANAGER_H

#include <stdint.h>
#include <stdbool.h>
#include "stm32l5xx.h"
#include "secboot_aes.h"
#include "secboot_sha256.h"
#include "secboot_ecdsa.h"
#include "secboot_crc.h"
#include "secure_nsc.h"
#include "secboot_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Constants ----------------------------------------------------------------*/

/** @defgroup BOOTLOADER_Constants Bootloader Constants
  * @{
  */
#define BOOTLOADER_START_ADDR     0x0C000000UL   /**< Secure bootloader start address in flash */
#define BOOTLOADER_SIZE           32*1024        /**< Bootloader size in bytes (32KB) */
#define AES_KEY_OFFSET            (BOOTLOADER_START_ADDR+0x8000)  /**< AES key storage offset */
#define AES_KEY_SIZE              32              /**< AES-256 key size in bytes */
#define AES_IV_OFFSET             (BOOTLOADER_START_ADDR+0x8020)  /**< AES IV storage offset */
#define AES_IV_SIZE               16              /**< AES IV size in bytes */
#define ECC_PUBKEY_OFFSET         (BOOTLOADER_START_ADDR+0x8030)  /**< ECC public key offset */
#define ECC_PUBKEY_SIZE           64              /**< ECC P-256 public key size in bytes */
#define BOOTLOADER_CRC_OFFSET     (BOOTLOADER_START_ADDR+0x8070)  /**< Bootloader CRC offset */
#define FW_MAGIC_NUMBER           0xDEADBEEF      /**< Firmware magic number identifier */
#define FW_VERSION_SIZE           4               /**< Firmware version field size */
#define FW_HASH_SIZE              32              /**< SHA-256 hash size */
#define FW_SIGNATURE_SIZE         64              /**< ECDSA P-256 signature size */
#define VTOR_TABLE_APP_START_ADDR 0x08040100UL    /**< Application vector table start */
#define APP_START_ADDRESS         0x08040100UL    /**< Application start address in flash */
#define APP_IMAGE_START_ADDRESS   0x08040000UL    /**< Application Image start address in flash */
/**
  * @}
  */

/* Type Definitions ---------------------------------------------------------*/

/** @defgroup BOOTLOADER_Types Type Definitions
  * @{
  */

/** 
  * @brief Non-secure callable function pointer type
  * @note CMSE_NS_CALL indicates this function pointer will call into Non-Secure code
  */
#define CMSE_NS_CALL  __attribute((cmse_nonsecure_call))
#define CMSE_NS_ENTRY __attribute((cmse_nonsecure_entry))
typedef void CMSE_NS_CALL (*funcptr)(void);

/** 
  * @brief Typedef for non-secure callback functions 
  */
typedef funcptr funcptr_NS;

/** @defgroup BOOTLOADER_Status Status Codes
  * @{
  */
typedef enum {
    SECBOOT_BOOTMANAGER_OK = 0x00,               /**< Operation successful */
    SECBOOT_BOOTMANAGER_ERROR,                   /**< General error */
    SECBOOT_BOOTMANAGER_INVALID_SIGNATURE,      /**< Cryptographic signature verification failed */
    SECBOOT_BOOTMANAGER_INVALID_HASH,           /**< Firmware hash verification failed */
    SECBOOT_BOOTMANAGER_INVALID_HEADER,         /**< Firmware header is corrupted */
    SECBOOT_BOOTMANAGER_FLASH_ERROR,            /**< Flash operation failed */
    SECBOOT_BOOTMANAGER_INVALID_CRC,            /**< CRC operation failed */
    SECBOOT_BOOTMANAGER_DECRYPTION_ERROR,       /**< Firmware decryption failed */
    SECBOOT_BOOTMANAGER_VERSION_ROLLBACK,       /**< Attempt to install older firmware version */
    SECBOOT_BOOTMANAGER_SECURE_VIOLATION,       /**< TrustZone security violation */
    SECBOOT_BOOTMANAGER_HW_SECURE_FAULT,        /**< Hardware security fault detected */
    SECBOOT_BOOTMANAGER_JUMP_FAILED             /**< Failed to jump to application */
} SECBOOT_BOOTMANAGER_StatusTypeDef;
/**
  * @}
  */

/** @defgroup BOOTLOADER_Structures Data Structures
  * @{
  */

/**
  * @brief  Firmware header structure containing security metadata
  */
typedef struct __attribute__((packed)) {
    uint32_t magicNumber;       /**< Magic number to identify valid firmware (FW_MAGIC_NUMBER) */
    uint32_t imageSize;         /**< Complete firmware image size including header */
    uint8_t  version[FW_VERSION_SIZE];  /**< Firmware version (4 bytes) */
    uint32_t entryPoint;        /**< Application entry point address */
    uint8_t  firmwareHash[FW_HASH_SIZE];  /**< SHA-256 hash of firmware payload */
    uint8_t  signature[FW_SIGNATURE_SIZE]; /**< ECDSA signature of firmware header */
    uint32_t headerCRC;         /**< CRC32 of this header (excluding this field) */
} FirmwareHeader_TypeDef;

typedef struct __attribute__((packed)) {
    uint32_t AES_key[4];   
    uint32_t AES_iv[4];        
} AES_Secrets_TypeDef;
/**
  * @}
  */

/* Function Prototypes ------------------------------------------------------*/

/** @addtogroup BOOTLOADER_Core_Functions
  * @{
  */

/**
  * @brief  Initialize the secure bootloader environment
  * @note   This function must be called before any other bootloader operations.
  *         It initializes cryptographic hardware, flash interface, and security peripherals.
  * @param  None
  * @retval SECBOOT_BOOTMANAGER_StatusTypeDef Boot status code
  */
SECBOOT_BOOTMANAGER_StatusTypeDef SECBOOT_BootManager_Init(void);



/**
  * @brief  Verify the bootloader CRC integrity using predefined addresses
  * @note   This function:
  *         - Checks CRC of fixed bootloader range against stored value
  *         - Uses hardware CRC-32 with STM32 hardware acceleration
  *         - Implements secure comparison with timing attack protection
  *         - Validates flash boundaries before computation
  * @retval SECBOOT_BOOTMANAGER_StatusTypeDef Verification status
  */
SECBOOT_BOOTMANAGER_StatusTypeDef SECBOOT_BootManager_VerifyBootloaderCRC(void);



/**
  * @brief  Verify the integrity and authenticity of the firmware image
  * @note   Performs cryptographic signature verification and hash check of the application.
  *         Uses hardware-accelerated cryptography where available.
  * @retval SECBOOT_BOOTMANAGER_StatusTypeDef Verification status code
  */
SECBOOT_BOOTMANAGER_StatusTypeDef SECBOOT_BootManager_VerifyAppSignature(uint32_t image_address);

/**
  * @brief  Decrypt and flash the firmware image to target address
  * @note   Uses AES-256 in CTR mode for firmware decryption during flashing.
  *         Performs automatic flash erase and write operations.
  * @param  srcAddr Source address of encrypted firmware
  * @param  destAddr Destination address in flash memory
  * @param  size Size of firmware image in bytes
  * @param  key Pointer to AES-256 key (32 bytes)
  * @param  iv Pointer to initialization vector (16 bytes)
  * @retval SECBOOT_BOOTMANAGER_StatusTypeDef Flash operation status code
  */
SECBOOT_BOOTMANAGER_StatusTypeDef SECBOOT_BootManager_FlashFirmware(
    uint32_t srcAddr, 
    uint32_t destAddr, 
    uint32_t size, 
    const uint8_t* key, 
    const uint8_t* iv);

/**
  * @brief  Jump to the application firmware
  * @note   Configures the MSP and vector table before jumping. Performs final
  *         security checks before transferring control to the application.
  * @param  appAddr Address of the application vector table
  * @retval None (does not return if successful)
  */
SECBOOT_BOOTMANAGER_StatusTypeDef SECBOOT_BootManager_JumpTo(uint32_t image_address);

/**
  * @brief  Perform secure firmware update
  * @note   Complete firmware update procedure including verification, flashing,
  *         and integrity checks. Handles both full and delta updates.
  * @param  fwHeader Pointer to the new firmware header structure
  * @param  fwData Pointer to the new firmware data
  * @retval SECBOOT_BOOTMANAGER_StatusTypeDef Update process status code
  */
SECBOOT_BOOTMANAGER_StatusTypeDef SECBOOT_BootManager_UpdateFirmware(FirmwareHeader_TypeDef* fwHeader, uint8_t* fwData);

/**
  * @brief  Check for firmware rollback protection
  * @note   Compares version numbers using semantic versioning rules to prevent
  *         installation of older firmware versions.
  * @param  currentVersion Current firmware version (4-byte array)
  * @param  newVersion New firmware version (4-byte array)
  * @retval SECBOOT_BOOTMANAGER_StatusTypeDef Rollback check status code
  */
SECBOOT_BOOTMANAGER_StatusTypeDef SECBOOT_BootManager_CheckRollbackProtection(uint8_t* currentVersion, uint8_t* newVersion);

/**
  * @}
  */

#ifdef __cplusplus
}
#endif

#endif 
/* SECBOOT_BOOTMANAGER_H */

