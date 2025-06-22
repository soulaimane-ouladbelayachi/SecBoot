#include "secboot_diag.h"


/**
  * @brief  Basic response executor
  */
static void SECBOOT_Diag_ExecuteResponse(SECBOOT_Diag_ResponseLevel level);


/**
  * @brief  Recovery attempt with logging
  * @note   Verifies backup and jumps, logs critical events
  */
static void try_recovery_from_backup(void);

/**
  * @brief  Basic system lockdown
  * @note   Performs essential security actions without complex features
  */
void system_lockdown(void);

SECBOOT_Diag_TypeDef SECBOOT_Diag_LogEvent(SECBOOT_Diag_EventType event,uint8_t code,uint32_t data){
     /* 1. Validate parameters */
    if (event > SECBOOT_DIAG_ROLLBACK_ATTEMPT) {
        return SECBOOT_DIAG_INVALID_PARAM;
    }

    /* 2. Prepare log entry */
    SECBOOT_Diag_LogEntry entry;
    entry.timestamp = HAL_GetTick();
    entry.event = event;
    entry.error_code = code;
    entry.context_data = data;
    entry.crc = 0;  // Temporary zero for CRC calculation


    uint32_t temp_crc;
    memcpy(&temp_crc, &entry.crc, sizeof(temp_crc));  // Safe

    //TODO FIX ALIGNEMENT SECBOOT_Diag_LogEntry

    if(SECBOOT_CRC_Calculate((uint8_t*)&entry, (sizeof(entry) - sizeof(entry.crc)), &temp_crc) != SECBOOT_CRC_OK){
        return SECBOOT_DIAG_ERROR;
    }

    /* 4. Secure flash programming */
    HAL_FLASH_Unlock();

    /* 4.1 Get next log position (circular buffer) */
    static uint32_t log_index = 0;
    uint32_t log_addr = SECBOOT_DIAG_LOG_BASE + (log_index * SECBOOT_DIAG_LOG_SIZE);

    /* 4.2 Verify sector is erased */
    if (*(uint32_t*)log_addr != 0xFFFFFFFF) {
        HAL_FLASH_Lock();
        return SECBOOT_DIAG_TAMPERED;
    }

    /* 4.3 Program entry in 64-bit chunks (STM32L5 requirement) */
    uint64_t* pData = (uint64_t*)&entry;
    for (uint8_t i = 0; i < SECBOOT_DIAG_LOG_SIZE/8; i++) {
        if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_DOUBLEWORD, log_addr + (i * 8), pData[i]) != HAL_OK) {
            HAL_FLASH_Lock();
            return SECBOOT_DIAG_ERROR;
        }
    }

    HAL_FLASH_Lock();

    /* 5. Update index with overflow protection */
    log_index = (log_index + 1) % SECBOOT_DIAG_MAX_LOGS;

    /* 6. Verify write (anti-tamper measure) */
    SECBOOT_Diag_LogEntry written_entry;
    memcpy(&written_entry, (void*)log_addr, sizeof(written_entry));
    
    uint32_t verify_crc = 0;

    if(SECBOOT_CRC_Calculate((uint8_t*)&written_entry,(sizeof(written_entry) - sizeof(written_entry.crc)),&verify_crc) != SECBOOT_CRC_OK){
        return SECBOOT_DIAG_ERROR;
    }                                      

    if (written_entry.crc != verify_crc) {
        return SECBOOT_DIAG_TAMPERED;
    }

    return SECBOOT_DIAG_OK;

}



/**
  * @brief  Handles CRC verification failures with basic response policy
  * @param  status CRC error status from verification
  * @retval SECBOOT_Diag_ResponseLevel Recommended system response
  *
  * @note Simplified Response Policy:
  * - CRC mismatch: Try recovery once
  * - Invalid parameters: Just log warning
  * - Timeout/other errors: Lock system
  */
SECBOOT_Diag_ResponseLevel SECBOOT_Diag_HandleCrcFail(SECBOOT_CRC_StatusTypeDef status)
{
    // 1. Always log the failure first
    SECBOOT_Diag_LogEvent(SECBOOT_DIAG_CRC_FAIL, (uint8_t)status, HAL_GetTick());
    
    // 2. Determine simple response
    SECBOOT_Diag_ResponseLevel response;
    
    if (status == SECBOOT_CRC_MISMATCH) {
        response = SECBOOT_DIAG_RESP_RECOVER;  // Try recovery
    }
    else if (status == SECBOOT_CRC_INVALID_PARAM) {
        response = SECBOOT_DIAG_RESP_WARN;     // Just log warning
    }
    else {
        response = SECBOOT_DIAG_RESP_LOCKDOWN; // Lock system for other errors
    }
    
    // 3. Execute the response
    SECBOOT_Diag_ExecuteResponse(response);
    
    return response;
}

/**
  * @brief  Basic response executor
  */
void SECBOOT_Diag_ExecuteResponse(SECBOOT_Diag_ResponseLevel level)
{
    switch(level) {
        case SECBOOT_DIAG_RESP_WARN:
            // Just blink LED for visibility
            HAL_GPIO_WritePin(GPIOD, GPIO_PIN_3, GPIO_PIN_RESET);
            break;
            
        case SECBOOT_DIAG_RESP_RECOVER:
            try_recovery_from_backup();
            break;
            
        case SECBOOT_DIAG_RESP_LOCKDOWN:
            system_lockdown();
            break;
            
        default:
            break;
    }
}


/**
  * @brief  Recovery attempt with logging
  * @note   Verifies backup and jumps, logs critical events
  */
void try_recovery_from_backup(void)
{
    // 1. Log recovery attempt start
    SECBOOT_Diag_LogEvent(SECBOOT_DIAG_ROLLBACK_ATTEMPT, 
                         ROLLBACK_NORMAL_RECOVERY,  // Basic attempt code
                         HAL_GetTick());

    // 2. Verify backup signature
    if(SECBOOT_BootManager_VerifyAppSignature(SECBOOT_BACKUP_IMAGE_ADDR) != SECBOOT_BOOTMANAGER_OK)
    {
        // 3. Log signature failure
        SECBOOT_Diag_LogEvent(SECBOOT_DIAG_ROLLBACK_ATTEMPT,
                             SIG_FAIL_BACKUP_IMAGE,  // Signature fail code
                             0);
        SECBOOT_Diag_ExecuteResponse(SECBOOT_DIAG_RESP_LOCKDOWN);
        return;
    }

    // 4. Attempt jump to backup
    if(SECBOOT_BootManager_JumpTo(SECBOOT_BACKUP_IMAGE_ADDR) != SECBOOT_BOOTMANAGER_OK)
    {
        // 5. Log jump failure
        SECBOOT_Diag_LogEvent(SECBOOT_DIAG_ROLLBACK_ATTEMPT,
                             ROOLBACK_JUMP_FAILED,  // Jump fail code
                             HAL_GetTick());
    }

    // 6. Final fallback (should never reach here)
    SECBOOT_Diag_ExecuteResponse(SECBOOT_DIAG_RESP_LOCKDOWN);
    while(1);
}


/**
  * @brief  Basic system lockdown
  * @note   Performs essential security actions without complex features
  */
void system_lockdown(void)
{
    while(1);
}


/**
  * @brief  Handles ECDSA signature verification failures
  * @param  status ECDSA verification status code
  * @retval SECBOOT_Diag_ResponseLevel 
  *         LOCKDOWN for security failures, RECOVER for hardware issues
  *
  * @note Response Policy:
  * ┌──────────────────────────────┬──────────────────────┐
  * │ ECDSA Status                │ System Response      │
  * ├──────────────────────────────┼──────────────────────┤
  * │ VERIFICATION_FAIL           │ Lockdown             │
  * │ INVALID_SIGNATURE           │ Lockdown             │
  * │ INVALID_PUBKEY              │ Lockdown             │
  * │ PKA_TIMEOUT/COMP_ERROR      │ Recover              │
  * │ Other Errors                │ Lockdown             │
  * └──────────────────────────────┴──────────────────────┘
  */
SECBOOT_Diag_ResponseLevel SECBOOT_Diag_HandleSigFail(SECBOOT_ECDSA_StatusTypeDef status)
{
    uint8_t error_code;
    SECBOOT_Diag_ResponseLevel response;
    
    switch(status) {
        /* Critical security failures */
        case SECBOOT_ECDSA_VERIFICATION_FAIL:
            error_code = SIG_FAIL_MAIN_IMAGE;
            response = SECBOOT_DIAG_RESP_LOCKDOWN;
            break;
            
        case SECBOOT_ECDSA_INVALID_SIGNATURE:
            error_code = SIG_FAIL_CONFIG_SIGNATURE;
            response = SECBOOT_DIAG_RESP_LOCKDOWN;
            break;
            
        case SECBOOT_ECDSA_INVALID_PUBKEY:
            error_code = SIG_FAIL_KEY_EXPIRED; // Treat as key validity issue
            response = SECBOOT_DIAG_RESP_LOCKDOWN;
            break;
            
        /* Hardware recoverable errors */
        case SECBOOT_ECDSA_PKA_TIMEOUT:
        case SECBOOT_ECDSA_PKA_COMP_ERROR:
            error_code = SIG_FAIL_HW_CRYPTO_ERROR;
            response = SECBOOT_DIAG_RESP_RECOVER;
            break;
            
        /* Default lockdown for other errors */
        default:
            error_code = 0x2F; // Unknown signature error
            response = SECBOOT_DIAG_RESP_LOCKDOWN;
            break;
    }
    
    /* Log with precise error code and raw status */
    SECBOOT_Diag_LogEvent(SECBOOT_DIAG_SIG_FAIL, 
                         error_code,
                         (uint32_t)status);
    
    /* Execute determined response */
    SECBOOT_Diag_ExecuteResponse(response);
    return response;
}
