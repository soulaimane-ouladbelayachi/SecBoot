#ifndef PRIME256V1_H
#define PRIME256V1_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Structure holding ECC curve parameters (NIST P-256 / prime256v1)
 */
typedef struct {
    const uint8_t *prime;      /*!< Prime modulus P */
    uint32_t prime_len;        /*!< Length of P in bytes */

    const uint8_t *A;          /*!< Curve coefficient A */
    const uint8_t *absA;       /*!< Absolute value of A (for PKA hardware) */
    uint32_t A_len;            /*!< Length of A in bytes */
    uint32_t A_sign;           /*!< Sign of A (used by PKA) */

    const uint8_t *B;          /*!< Curve coefficient B */
    uint32_t B_len;            /*!< Length of B in bytes */

    const uint8_t *G;          /*!< Base point G in uncompressed format */
    uint32_t G_len;            /*!< Length of G */

    const uint8_t *Gx;         /*!< X-coordinate of G */
    uint32_t Gx_len;           /*!< Length of Gx */

    const uint8_t *Gy;         /*!< Y-coordinate of G */
    uint32_t Gy_len;           /*!< Length of Gy */

    const uint8_t *order;      /*!< Order of G */
    uint32_t order_len;        /*!< Length of order */

    uint32_t cofactor;         /*!< Curve cofactor */

    const uint8_t *seed;       /*!< Optional curve seed */
    uint32_t seed_len;         /*!< Length of seed */
} ECC_Curve_Parameters;

/**
 * @brief Provides pointer to initialized prime256v1 curve parameters
 * 
 * @return const ECC_Curve_Parameters* Pointer to the curve parameters
 */
const ECC_Curve_Parameters* get_prime256v1_curve(void);

#ifdef __cplusplus
}
#endif

#endif /* PRIME256V1_H */