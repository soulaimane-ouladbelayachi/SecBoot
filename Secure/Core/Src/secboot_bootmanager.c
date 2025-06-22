#include "secboot_bootmanager.h"



static void bytes_to_uint32_be(uint8_t *input, size_t input_len, uint32_t *output);
/**
  * @brief  Securely retrieves and decrypts the AES key from protected storage
  * @retval SECBOOT_AES_StatusTypeDef Operation status
  */
static SECBOOT_AES_StatusTypeDef get_AES_key(AES_Secrets_TypeDef *AES_secret);


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


SECBOOT_AES_StatusTypeDef get_AES_key(AES_Secrets_TypeDef *AES_secret){


    /* All sensitive variables declared volatile to prevent optimization */
    SECBOOT_AES_Context AES_ctx = {0};
    uint32_t Aes_key[KEY_WORD_SIZE] = {0};
    uint32_t Aes_iv[AES_IV_SIZE] = {0};
    volatile uint32_t temp_key[4] = {0};
    volatile uint32_t temp_iv[AES_IV_SIZE/sizeof(uint32_t)] = {0};
    volatile uint8_t decrypted_key[AES_KEY_SIZE] = {0};
    SECBOOT_AES_StatusTypeDef status = SECBOOT_AES_ERROR;
    bool aes_initialized = false;

    /* 1. Create temporary key from device UID - volatile ensures no optimization */
    temp_key[0] = HAL_GetUIDw0();
    temp_key[1] = HAL_GetUIDw1();
    temp_key[2] = HAL_GetUIDw2();
    temp_key[3] = FW_MAGIC_NUMBER;

  

    memcpy((uint32_t*)temp_iv, (uint32_t*)AES_IV_OFFSET, AES_IV_SIZE);

    memcpy((uint32_t*)Aes_iv, (uint32_t*)AES_IV_OFFSET, AES_IV_SIZE);



    /* 3. Initialize AES context with temporary key */
        if (SECBOOT_AES_Init(&AES_ctx, (uint32_t*)temp_key, (uint32_t*)temp_iv) == SECBOOT_AES_OK) {
            aes_initialized = true;
            
            /* 4. Decrypt the master key with size validation */
            size_t decrypted_key_len = 0;
            if (SECBOOT_AES_Decrypt(&AES_ctx,
                                  (uint32_t)AES_KEY_OFFSET,
                                  AES_KEY_SIZE/sizeof(uint32_t),
                                  (uint8_t*)decrypted_key,
                                  &decrypted_key_len) == SECBOOT_AES_OK) {
                
                /* 5. Convert and validate decrypted key */
                bytes_to_uint32_be((uint8_t*)decrypted_key, decrypted_key_len, Aes_key);
                
                /* Key validation - check for all zeros and FFFF patterns */
                bool valid_key = false;
                for (size_t i = 0; i < (AES_KEY_SIZE/sizeof(uint32_t)); i++) {
                    if (Aes_key[i] != 0x00000000 && Aes_key[i] != 0xFFFFFFFF) {
                        valid_key = true;
                        break;
                    }
                }
                
                if (valid_key) {
                    status = SECBOOT_AES_OK;
                } else {
                    status = SECBOOT_AES_ERROR;
                }
            }
        }
    

    /* 6. Secure memory cleanup - volatile ensures this won't be optimized out */
    for (size_t i = 0; i < sizeof(temp_key)/sizeof(temp_key[0]); i++) {
        temp_key[i] = 0x00000000;
    }
    
    for (size_t i = 0; i < sizeof(temp_iv)/sizeof(temp_iv[0]); i++) {
        temp_iv[i] = 0x00000000;
    }
    
    for (size_t i = 0; i < sizeof(decrypted_key); i++) {
        decrypted_key[i] = 0x00;
    }

    memcpy((uint32_t*)AES_secret->AES_iv,(uint32_t*)Aes_iv,AES_IV_SIZE);
    memcpy((uint32_t*)AES_secret->AES_key,Aes_key,(uint32_t*)AES_IV_SIZE);

    if(SECBOOT_AES_DeInit(&AES_ctx) != SECBOOT_AES_OK){
        status = SECBOOT_AES_ERROR;
    }

    return status;

}
/**
  * @brief  Initialize the secure bootloader environment
  * @note   This critical function:
  *         - Configures hardware security features
  *         - Initializes cryptographic accelerators
  *         - Sets up TrustZone security boundaries
  *         - Must be called before any other bootloader operation
  * @retval SECBOOT_BOOTMANAGER_StatusTypeDef Initialization status
  */
SECBOOT_BOOTMANAGER_StatusTypeDef SECBOOT_BootManager_Init(void)
{
    SECBOOT_BOOTMANAGER_StatusTypeDef status = SECBOOT_BOOTMANAGER_OK;
    MPCBB_ConfigTypeDef MPCBB_Config = {0};

    /* 1. Configure Peripheral Security Attributes */
    const uint32_t secure_peripherals[] = {
        GTZC_PERIPH_USART1,    /* Secure debug channel */
        GTZC_PERIPH_CRC,       /* Integrity checking */
        GTZC_PERIPH_ICACHE_REG,/* Instruction cache */
        GTZC_PERIPH_AES,       /* Crypto acceleration */
        GTZC_PERIPH_HASH,      /* Cryptographic hashing */
        GTZC_PERIPH_RNG,       /* True random number gen */
        GTZC_PERIPH_PKA        /* Public key acceleration */
    };

    for (size_t i = 0; i < sizeof(secure_peripherals)/sizeof(secure_peripherals[0]); i++) {
        if (HAL_GTZC_TZSC_ConfigPeriphAttributes(secure_peripherals[i], 
                GTZC_TZSC_PERIPH_SEC|GTZC_TZSC_PERIPH_NPRIV) != HAL_OK) {
            status = SECBOOT_BOOTMANAGER_SECURE_VIOLATION;
            break;
        }
    }

    /* 2. Configure SRAM Memory Protection */
    if (status == SECBOOT_BOOTMANAGER_OK) {
        /* SRAM1: First 12 blocks secure, remaining non-secure */
        MPCBB_Config.SecureRWIllegalMode = GTZC_MPCBB_SRWILADIS_ENABLE;
        MPCBB_Config.InvertSecureState = GTZC_MPCBB_INVSECSTATE_NOT_INVERTED;
        
        /* Set secure areas (0xFFFFFFFF) and non-secure (0x00000000) */
        memset(MPCBB_Config.AttributeConfig.MPCBB_SecConfig_array, 0xFF, 12*sizeof(uint32_t));
        memset(&MPCBB_Config.AttributeConfig.MPCBB_SecConfig_array[12], 0x00, 12*sizeof(uint32_t));
        MPCBB_Config.AttributeConfig.MPCBB_LockConfig_array[0] = 0x00000000;

        if (HAL_GTZC_MPCBB_ConfigMem(SRAM1_BASE, &MPCBB_Config) != HAL_OK) {
            status = SECBOOT_BOOTMANAGER_SECURE_VIOLATION;
        }
    }

    /* 3. Configure SRAM2 (Entirely non-secure) */
    if (status == SECBOOT_BOOTMANAGER_OK) {
        memset(MPCBB_Config.AttributeConfig.MPCBB_SecConfig_array, 0x00, 8*sizeof(uint32_t));
        if (HAL_GTZC_MPCBB_ConfigMem(SRAM2_BASE, &MPCBB_Config) != HAL_OK) {
            status = SECBOOT_BOOTMANAGER_SECURE_VIOLATION;
        }
    }

    /* 4. Initialize Cryptographic Modules */
    if (status == SECBOOT_BOOTMANAGER_OK) {
        if (SECBOOT_ECDSA_Init() != SECBOOT_ECDSA_OK) {
            status = SECBOOT_BOOTMANAGER_HW_SECURE_FAULT;
        }
    }

    if (status == SECBOOT_BOOTMANAGER_OK) {
        if (SECBOOT_CRC_Init() != SECBOOT_CRC_OK) {
            status = SECBOOT_BOOTMANAGER_HW_SECURE_FAULT;
        }
    }

    if (status == SECBOOT_BOOTMANAGER_OK) {
        if (SECBOOT_SHA256_Init() != SECBOOT_SHA256_OK) {
            status = SECBOOT_BOOTMANAGER_HW_SECURE_FAULT;
        }
    }


    return status;
}



SECBOOT_BOOTMANAGER_StatusTypeDef SECBOOT_BootManager_VerifyBootloaderCRC(){

    /* Predefined addresses - adjust according to your memory map */
    const uint32_t Bootloader_start = BOOTLOADER_START_ADDR;  /* Start of bootloader */
    const uint32_t Bootloader_size  = BOOTLOADER_SIZE;  /* 48KB bootloader size */
    const uint32_t stored_crc_addr  = BOOTLOADER_CRC_OFFSET;  /* Last 4 bytes of bootloader sector */

    uint32_t stored_crc = 0;
    uint32_t computed_crc = 0;

    if(SECBOOT_CRC_Calculate((uint32_t*)Bootloader_start,Bootloader_size,&computed_crc) != SECBOOT_CRC_OK){
        return SECBOOT_BOOTMANAGER_ERROR;
    }

    stored_crc = *(uint32_t*)stored_crc_addr;


    if(stored_crc == computed_crc){

        return SECBOOT_BOOTMANAGER_OK;

    }else{
        return SECBOOT_BOOTMANAGER_INVALID_CRC;
    }

}


SECBOOT_BOOTMANAGER_StatusTypeDef SECBOOT_BootManager_VerifyAppSignature(uint32_t image_address)
{
    // Initialize status to error as default (fail-safe)
    SECBOOT_BOOTMANAGER_StatusTypeDef status = SECBOOT_BOOTMANAGER_ERROR;

    // Buffer to store computed SHA-256 hash of application
    uint8_t pDigitApp[FW_HASH_SIZE] = {0};

    // Pointer to firmware header structure in flash memory
    const FirmwareHeader_TypeDef* pAppHeader = (const FirmwareHeader_TypeDef*)image_address;
    // Pointer to start of application binary in flash
    uint8_t* pAppBinary = (uint8_t*)(pAppHeader->entryPoint);

    // 1. First check: Verify firmware header magic number
    if(pAppHeader->magicNumber != FW_MAGIC_NUMBER) {
        status = SECBOOT_BOOTMANAGER_INVALID_HEADER;
        return status; // Early return if header is invalid
    }

    // 2. Second check: Compute and verify SHA-256 hash
    // Compute hash of application binary using hardware accelerator
    if(SECBOOT_SHA256_Compute(pAppBinary,pAppHeader->imageSize,pDigitApp) != SECBOOT_SHA256_OK){
        status = SECBOOT_BOOTMANAGER_ERROR;
        return status; // Return if hash computation fails
    }

    // Compare computed hash with hash stored in firmware header
    if(memcmp((uint8_t*)pDigitApp,(uint8_t*)pAppHeader->firmwareHash,FW_HASH_SIZE) != 0){
        status = SECBOOT_BOOTMANAGER_INVALID_HASH;
        return status; // Return if hashes don't match
    }

    // 3. Third check: Verify ECDSA signature
    // Get public key from predefined secure location
    SECBOOT_ECC_PublicKey *public_key = (SECBOOT_ECC_PublicKey*) ECC_PUBKEY_OFFSET;
    // Get signature from firmware header
    SECBOOT_ECC_Signature *signature = (SECBOOT_ECC_Signature*) pAppHeader->signature;

    // Verify signature using ECDSA
    if(SECBOOT_ECDSA_Verify_Signature(pDigitApp,FW_HASH_SIZE,signature,public_key) == SECBOOT_ECDSA_VERIFICATION_SUCCESS){
        status = SECBOOT_BOOTMANAGER_OK; // All verifications passed
    }else{
        status = SECBOOT_BOOTMANAGER_INVALID_SIGNATURE;
        return status; // Return if signature verification fails
    }

    // Security cleanup: Wipe sensitive data from memory
    memset((uint8_t*)pDigitApp,0,FW_HASH_SIZE); // Clear computed hash
    memset((SECBOOT_ECC_PublicKey*)public_key,0,sizeof(SECBOOT_ECC_PublicKey)); // Clear public key copy
    memset((SECBOOT_ECC_Signature*)signature,0,sizeof(SECBOOT_ECC_Signature)); // Clear signature copy

    return status; // Return final verification status
}


SECBOOT_BOOTMANAGER_StatusTypeDef SECBOOT_BootManager_JumpTo(uint32_t jump_to_address)
{

    funcptr_NS NonSecureApp_ResetHandler;
    
    /* 2. Get pointer to application header in flash */
    const FirmwareHeader_TypeDef* pAppHeader = (const FirmwareHeader_TypeDef*)jump_to_address;

    /* 4. Configure non-secure vector table */
    SCB_NS->VTOR = pAppHeader->entryPoint;

    /* 5. Set non-secure main stack pointer (MSP_NS) */
    uint32_t ns_msp = *((uint32_t *)pAppHeader->entryPoint);

    __TZ_set_MSP_NS(ns_msp);

    /* Get non-secure reset handler */
    NonSecureApp_ResetHandler = (funcptr_NS)(*((uint32_t *)((pAppHeader->entryPoint) + 4U)));


    /* 9. Jump to non-secure application */
    NonSecureApp_ResetHandler();

    /* 10. Should never reach here - return error if we do */
    return SECBOOT_BOOTMANAGER_JUMP_FAILED;
}