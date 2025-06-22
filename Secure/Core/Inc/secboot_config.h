/**
  * @file    secboot_config.h
  * @brief   Secure Boot Configuration for STM32L5
  * @version 1.0
  * @date    2025-06-15
  * @author  Soulaimane Oulad Belayachi
  *
  */

#ifndef SECBOOT_CONFIG_H
#define SECBOOT_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

/* Memory Layout ----------------------------------------------------------*/
#define SECBOOT_BOOTLOADER_ADDR        0x0C000000UL  /* Secure bootloader area */
#define SECBOOT_DIAG_LOG_BASE          0x0C00A000UL  /* Last 2KB sector */

#define SECBOOT_MAIN_APP_IMAGE_ADDR    0x08040000UL  // Start address of the main application image
#define SECBOOT_MAIN_APP_IMAGE_SIZE    (50 * 1024)   // Size of the main application image (50KB)

#define SECBOOT_SLOT1_ADDR             0x0804D000UL  // Start address of slot 1 (for firmware update or redundancy)
#define SECBOOT_SLOT1_SIZE             (50 * 1024)   // Size of slot 1 (50KB)

#define SECBOOT_SLOT2_ADDR             0x08059000UL  // Start address of slot 2 (alternative firmware slot)
#define SECBOOT_SLOT2_SIZE             (50 * 1024)   // Size of slot 2 (50KB)

#define SECBOOT_UPDATE_SLOT_ADDR       0x08066000UL  // Start address of update slot (temporary storage for new firmware)
#define SECBOOT_UPDATE_SLOT_SIZE       (50 * 1024)   // Size of update slot (50KB)

#define SECBOOT_BACKUP_IMAGE_ADDR      0x08073000UL  // Start address of backup image (used for recovery)
#define SECBOOT_BACKUP_IMAGE_SIZE      (50 * 1024)   // Size of backup image (50KB)



#define SECBOOT_DIAG_LOG_SIZE          64    /* Bytes per log entry */
#define SECBOOT_DIAG_MAX_LOGS          16    /* Circular buffer size */

/* Bootloader Layout ----------------------------------------------------------*/
#define BOOTLOADER_START_ADDR          0x0C000000UL   /**< Secure bootloader start address in flash */
#define BOOTLOADER_SIZE                32*1024        /**< Bootloader size in bytes (32KB) */


/* Firmware Identification -----------------------------------------------*/
#define SECBOOT_FW_MAGIC_NUMBER        0xDEADBEEFUL  /* Unique firmware marker */
#define SECBOOT_FW_HEADER_SIZE         256           /* Bytes */

/* Security Settings -----------------------------------------------------*/
#define SECBOOT_MAX_CRC_FAILURES       3             /* Before lockdown */
#define SECBOOT_MAX_SIG_FAILURES       1             /* Zero tolerance */
#define SECBOOT_TAMPER_FLAG_ADDR       (SECBOOT_DIAG_LOG_ADDR + 0x1F00) /* Last 256b */

/* TrustZone Configuration -----------------------------------------------*/
#define SECBOOT_SECURE_AREA_START      0x0C000000UL  /* TZ-Secure area */
#define SECBOOT_SECURE_AREA_SIZE       (32 * 1024)  /* 32KB secure flash */

/* Cryptographic Constants ----------------------------------------------*/
#define AES_KEY_OFFSET            (BOOTLOADER_START_ADDR+0x8000)  /**< AES key storage offset */
#define AES_KEY_SIZE              32              /**< AES-256 key size in bytes */
#define AES_IV_OFFSET             (BOOTLOADER_START_ADDR+0x8020)  /**< AES IV storage offset */
#define AES_IV_SIZE               16              /**< AES IV size in bytes */
#define ECC_PUBKEY_OFFSET         (BOOTLOADER_START_ADDR+0x8030)  /**< ECC public key offset */
#define ECC_PUBKEY_SIZE           64              /**< ECC P-256 public key size in bytes */
#define BOOTLOADER_CRC_OFFSET     (BOOTLOADER_START_ADDR+0x8070)  /**< Bootloader CRC offset */

/* Boot Policy ----------------------------------------------------------*/
#define SECBOOT_BOOT_DELAY_MS          100           /* Anti-glitch delay */
#define SECBOOT_MIN_FW_VERSION         0x00010000    /* v1.0.0.0 */

/* Debug Controls -------------------------------------------------------*/
#ifdef SECBOOT_DEBUG
  #define SECBOOT_ALLOW_DEBUG          1             /* Enable debug in dev */
  #define SECBOOT_VERBOSE_LOGGING      1
#else
  #define SECBOOT_ALLOW_DEBUG          0             /* Disable in production */
  #define SECBOOT_VERBOSE_LOGGING      0
#endif

/* Hardware Protection --------------------------------------------------*/
#define SECBOOT_ENABLE_RDP_LEVEL_1     1             /* Read protection */
#define SECBOOT_ENABLE_WRP             1             /* Write protection */
#define SECBOOT_ENABLE_GTZC            1             /* TrustZone enable */


#ifdef __cplusplus
}
#endif

#endif /* SECBOOT_CONFIG_H */