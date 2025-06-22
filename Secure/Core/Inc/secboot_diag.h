/**
  * @file    secboot_diag.h
  * @brief   Secure Boot Diagnostics Module
  * @version 1.0
  * @date    2025-06-20
  * @author  Soulaimane Oulad Belayachi
  *
  * @note    Provides secure logging and response handling
  *          for boot verification failures
  */

#ifndef SECBOOT_DIAG_H
#define SECBOOT_DIAG_H

#include "stm32l5xx_hal.h"
#include "secboot_crc.h"
#include "secboot_ecdsa.h"
#include "secboot_config.h"
#include "secboot_bootmanager.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Status Type Definition ------------------------------------------------*/
typedef enum {
    SECBOOT_DIAG_OK = 0,
    SECBOOT_DIAG_ERROR,
    SECBOOT_DIAG_INVALID_PARAM,
    SECBOOT_DIAG_FLASH_FAIL,
    SECBOOT_DIAG_TAMPERED
} SECBOOT_Diag_TypeDef;

/* Constants ------------------------------------------------------------*/
#define SECBOOT_DIAG_LOG_SIZE      64    /* Bytes per log entry */
#define SECBOOT_DIAG_MAX_LOGS      16    /* Circular buffer size */

/* Event Types ---------------------------------------------------------*/
typedef enum {
    SECBOOT_DIAG_CRC_FAIL = 0x10,
    SECBOOT_DIAG_SIG_FAIL = 0x20,
    SECBOOT_DIAG_SECURE_VIOLATION = 0x30,
    SECBOOT_DIAG_ROLLBACK_ATTEMPT = 0x40
} SECBOOT_Diag_EventType;

/* Failure Codes ---------------------------------------------------------*/
typedef enum {
    CRC_FAIL_MAIN_IMAGE      = 0x10,  // Primary firmware CRC mismatch
    CRC_FAIL_BACKUP_IMAGE    = 0x11,  // Backup firmware CRC invalid
    CRC_FAIL_CONFIG_DATA     = 0x12,  // Configuration data corrupted
    CRC_FAIL_CRITICAL_SECRET = 0x13,  // Security-sensitive data corrupted
    CRC_FAIL_LOG_ENTRY       = 0x14   // Diagnostic log corruption
} CRC_FailureCodes;

typedef enum {
    SIG_FAIL_MAIN_IMAGE      = 0x20,  // Primary FW signature invalid
    SIG_FAIL_BACKUP_IMAGE    = 0x21,  // Backup FW signature invalid
    SIG_FAIL_CONFIG_SIGNATURE= 0x22,  // Config data signature fail
    SIG_FAIL_KEY_EXPIRED     = 0x23,  // Cryptographic key expiry
    SIG_FAIL_HW_CRYPTO_ERROR = 0x24   // PKA/CRC hardware fault
} Signature_FailureCodes;

typedef enum {
    SECURE_VIOLATION_MEMORY_TAMPER  = 0x30,  // Unauthorized memory access
    SECURE_VIOLATION_DEBUG_PORT     = 0x31,  // Secure debug triggered
    SECURE_VIOLATION_CLOCK_TAMPER   = 0x32,  // Clock glitching detected
    SECURE_VIOLATION_KEY_ACCESS     = 0x33,  // Illegal key access attempt
    SECURE_VIOLATION_STACK_OVERFLOW = 0x34   // Stack protection triggered
} SecureViolationCodes;

typedef enum {
    ROLLBACK_NORMAL_RECOVERY   = 0x40,  // Valid recovery initiated
    ROLLBACK_INVALID_SIGNATURE = 0x41,  // Backup image tampered
    ROLLBACK_VERSION_REJECTED  = 0x42,  // Anti-rollback protection
    ROLLBACK_HW_FAULT          = 0x43,  // Flash controller error
    ROLLBACK_UNAUTHORIZED_CMD  = 0x44,   // Illegal recovery request
    ROOLBACK_JUMP_FAILED        =0x45     //Jump to Backup Failed
} RollbackAttemptCodes;

/* Response Levels -----------------------------------------------------*/
typedef enum {
    SECBOOT_DIAG_RESP_NONE = 0,
    SECBOOT_DIAG_RESP_WARN,
    SECBOOT_DIAG_RESP_RECOVER,
    SECBOOT_DIAG_RESP_LOCKDOWN
} SECBOOT_Diag_ResponseLevel;

/* Log Entry Structure ------------------------------------------------*/
typedef struct {
    uint32_t timestamp;
    SECBOOT_Diag_EventType event;
    uint8_t error_code;
    uint32_t context_data;
    uint32_t crc;
} SECBOOT_Diag_LogEntry;


/* Function Prototypes ------------------------------------------------*/

/**
  * @brief  Log a security event
  * @param  event Event type
  * @param  code Error code
  * @param  data Context data
  * @retval SECBOOT_Diag_TypeDef Status
  */
SECBOOT_Diag_TypeDef SECBOOT_Diag_LogEvent(SECBOOT_Diag_EventType event,uint8_t code,uint32_t data);

/**
  * @brief  Handle CRC verification failure
  * @param  status CRC error status
  * @retval SECBOOT_Diag_ResponseLevel
  */
SECBOOT_Diag_ResponseLevel SECBOOT_Diag_HandleCrcFail(SECBOOT_CRC_StatusTypeDef status);

/**
  * @brief  Handle signature verification failure
  * @param  status Signature error status
  * @retval SECBOOT_Diag_ResponseLevel
  */
SECBOOT_Diag_ResponseLevel SECBOOT_Diag_HandleSigFail(SECBOOT_ECDSA_StatusTypeDef status);



#ifdef __cplusplus
}
#endif

#endif /* SECBOOT_DIAG_H */