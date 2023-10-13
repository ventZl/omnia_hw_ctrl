#pragma once

#include "cpu.h"
#include "gpio.h"
#include "svc.h"
#include "mkl81.h"
#include "clock.h"

typedef enum {
    LTC_SHA_1 = LTC0_MD_ALG_MDHA_SHA_1,
    LTC_SHA_224 = LTC0_MD_ALG_MDHA_SHA_224,
    LTC_SHA_256 = LTC0_MD_ALG_MDHA_SHA_256
} ltc_sha_mode_t;

typedef enum {
    LTC_OK,             /* Operation succeeded */
    LTC_BadRandomValue, /* Unsuitable random value, choose another and restart */
    LTC_Error,          /* LTC peripheral error, re-initialize it for further use */
    LTC_SignatureInvalid, /* Signature verification failed, signature either malformed or invalid */
    LTC_SignatureValid, /* Signature verification passed */
    LTC_KeyInvalid,     /* Public key provided is not valid */
    LTC_KeyValid        /* Public key provided is valid */
} ltc_pkha_result_t;

/* Type encapsulating long numbers used in PK. */
typedef struct {
    /* Binary image of the large integer.
     * The number herein is stored in a way that the lowest
     * offset of this array holds LSbyte of the number. More
     * significant bytes are then stored into following offsets
     * up to the MSbyte.
     * @note This array is forced to be 4-byte aligned so we can
     * do 32-bit loads and stores from/to it to speed things up.
     */
    uint8_t number[256] __attribute__((aligned(4)));

    /* Valid length of @ref number.
     * Only offsets 0 .. length - 1 hold valid bytes of the
     * large integer. 
     */
    unsigned length;     
} pkha_number_t;

typedef struct {
    pkha_number_t Gx;   /* x coord of curve base point */
    pkha_number_t Gy;   /* y coord of curve base point */
    pkha_number_t a;    /* a parameter of curve */
    pkha_number_t b;    /* b parameter of curve */
    pkha_number_t n;    /* n - order of [Gx, Gy] - modulus for integer operations */
    pkha_number_t p;    /* p - prime parameter of curve - modulus for curve operations */
} pkha_curve_t;

/* This struct only exist to minimize amount of 
 * ECDSA-related number of function arguments
 */
typedef struct {
    const pkha_number_t random_k; /* k - random value */
    const pkha_number_t pkey; /* private key */
    const pkha_number_t hash; /* z - message hash */
} pkha_sign_input_t;

typedef struct {
    const pkha_number_t Kx; /* public key point - x coord */
    const pkha_number_t Ky; /* public key point - y coord */
    const pkha_number_t hash; /* z - message hash */

} pkha_verify_input_t;

typedef struct {
    pkha_number_t c; /* a.k.a r - first part of digital signature */
    pkha_number_t d; /* a.k.a s - second part of digital signature */
} pkha_signature_t;

#define _REG_A              0
#define _REG_B              1
#define _REG_E              2
#define _REG_N              3

#define REGISTER_A          (_REG_A << 3)
#define REGISTER_B          (_REG_B << 3)
#define REGISTER_E          (_REG_E << 3)
#define REGISTER_N          (_REG_N << 3)
#define REGISTER_QUADRANT_0          0
#define REGISTER_QUADRANT_1          1
#define REGISTER_QUADRANT_2          2
#define REGISTER_QUADRANT_3          3
#define REGISTER_WHOLE               4

typedef enum {
	A0 = (REGISTER_A | REGISTER_QUADRANT_0),
	A1 = (REGISTER_A | REGISTER_QUADRANT_1),
	A2 = (REGISTER_A | REGISTER_QUADRANT_2),
	A3 = (REGISTER_A | REGISTER_QUADRANT_3),

	B0 = (REGISTER_B | REGISTER_QUADRANT_0),
	B1 = (REGISTER_B | REGISTER_QUADRANT_1),
	B2 = (REGISTER_B | REGISTER_QUADRANT_2),
	B3 = (REGISTER_B | REGISTER_QUADRANT_3),

	E = (REGISTER_E | REGISTER_QUADRANT_0),

	N0 = (REGISTER_N | REGISTER_QUADRANT_0),
	N1 = (REGISTER_N | REGISTER_QUADRANT_1),
	N2 = (REGISTER_N | REGISTER_QUADRANT_2),
	N3 = (REGISTER_N | REGISTER_QUADRANT_3),
} pkha_reg_t;

#define LTC_PKHA_ENGINE_ECC (0x800000)

/* Function codes for PKHA functions. Stated here as they
 * span multiple LTC_PKMD fields.
 */
#define LTC_PKHA_FUNC_COPY  (LTC_PKHA_ENGINE_ECC | 0b10000)
#define LTC_PKHA_FUNC_CLEAN (LTC_PKHA_ENGINE_ECC | 0b00001)

#define LTC_PKHA_FUNC_ADD   (LTC_PKHA_ENGINE_ECC | 0x00002)
#define LTC_PKHA_FUNC_SUB_1 (LTC_PKHA_ENGINE_ECC | 0x00003)
#define LTC_PKHA_FUNC_SUB_2 (LTC_PKHA_ENGINE_ECC | 0x00004)
#define LTC_PKHA_FUNC_MUL   (LTC_PKHA_ENGINE_ECC | 0x00405)
#define LTC_PKHA_FUNC_EXP   (LTC_PKHA_ENGINE_ECC | 0x00406)
#define LTC_PKHA_FUNC_AMODN (LTC_PKHA_ENGINE_ECC | 0x00007)
#define LTC_PKHA_FUNC_INV   (LTC_PKHA_ENGINE_ECC | 0x00008)
#define LTC_PKHA_FUNC_R2    (LTC_PKHA_ENGINE_ECC | 0x0000C)
#define LTC_PKHA_FUNC_GCD   (LTC_PKHA_ENGINE_ECC | 0x0000E)
#define LTC_PKHA_FUNC_PRIME (LTC_PKHA_ENGINE_ECC | 0x0000F)

#define LTC_PKHA_FUNC_ECC_MOD_ADD (LTC_PKHA_ENGINE_ECC | 0x00009)
#define LTC_PKHA_FUNC_ECC_MOD_DBL (LTC_PKHA_ENGINE_ECC | 0x0000A)
#define LTC_PKHA_FUNC_ECC_MOD_MUL (LTC_PKHA_ENGINE_ECC | 0x0040B)

#define LTC_PKHA_DEST_A     (0x00100)

/** Initialize the LTC peripheral.
 * This will enable clock to the LTC peripheral.
 */

__privileged void ltc_init(void);

SYSCALL(ltc_init)

/** Get status of LTC input FIFO 
 * @returns true if LTC input FIFO is full, false otherwise.
 */
static inline __privileged bool ltc_ififo_busy()
{
    return (BME_BITFIELD(LTC0_FIFOSTA, LTC0_FIFOSTA_IFF)); 
}

/** Get status of LTC being done with hash computation.
 * @returns true if LTC is done with HASH computation, false otherwise.
 */
static inline __privileged bool ltc_sha_done()
{
    return (BME_BITFIELD(LTC0_STA, LTC0_STA_DI)); 
}

/** Get status of LTC being busy doing hashing.
 * @returns true if LTC is either hashing or context contains hash results which
 * were not marked via clearing the DI flag. No next command can be issued in this state.
 * False is returned if LTC is free to process next command.
 */
static inline __privileged bool ltc_sha_busy()
{
    return (BME_BITFIELD(LTC0_STA, LTC0_STA_MB));
}

/** Tell if last operation ended in error.
 * @returns true if last operation ended due to the error. False otherwise.
 * @note If operation ended due to to the error, the only way to resume
 * LTC operation is to re-initialize the peripheral.
 */
static inline __privileged bool ltc_sha_error()
{
    return (BME_BITFIELD(LTC0_STA, LTC0_STA_EI));
}

/* Tell if last operation returned zero, or point at infinity.
 * @return true if the last PKHA operation result is either zero (ltc_mod_*)
 * or point at infinity (ltc_ecc_mod_*). False otherwise.
 */
static inline __privileged bool ltc_result_zero()
{
    return (BME_BITFIELD(LTC0_STA, LTC0_STA_PKZ));
}

/** Prepare the peripheral for hashing.
 * This functions allows to choose hashing function used (@ref ltc_sha_mode_t).
 * @param mode hashing function used (SHA-1, SHA-224 and SHA-256 are supported)
 * @param length overall data size in bytes.
 * @note Length is only used to determine how to set up peripheral for the 
 * process of hashing of the initial block, where there is difference if block
 * is shorter than 64 bytes. If you don't know size of the data in the advance
 * you can pass any value larger than 64 bytes and hashing will be successful
 * as long as you provide at least 64 bytes of data.
 */
__privileged void ltc_sha_start(ltc_sha_mode_t mode, uint32_t length);

SYSCALL(ltc_sha_start, ltc_sha_mode_t, uint32_t)

/** Return hash size of given hashing algorithm.
 * @param mode hashing function
 * @returns resulting hash size in bytes
 */
static inline uint32_t ltc_hash_size(ltc_sha_mode_t mode)
{
    switch (mode)
    {
        case LTC0_MD_ALG_MDHA_SHA_1:
            return 20;
            break;

        case LTC0_MD_ALG_MDHA_SHA_224:
            return 28;
            break;

        case LTC0_MD_ALG_MDHA_SHA_256:
            return 32;
            break;

        default:
            return 0;
    }
}

/** Provide chunk of data for hashing.
 * This function provides data for one round of hashing. Family of SHA hashing
 * functions uses blocks of 64 bytes for one round. If the overall data size
 * is not divisible by 64, then this function automatically manages to pad
 * the last block. It is an error to supply more data after incomplete (shorter
 * than 64 bytes-long) block has already been passed to this function without
 * calling @ref ltc_sha_start() previously.
 * @param data address of data to be hashed
 * @param length length of the data block
 * @returns true if data was processed by the LTC, false if there was an error.
 * @note This function will fail if LTC is not currently in hashing mode or
 * if unknown hashing algorithm is activated.
 }
 */
__privileged bool ltc_sha_data(const uint8_t * data, uint16_t length);


SYSCALL(ltc_sha_data, const uint8_t *, uint16_t)

/** Extract hash of provided data.
 * This function is called after all the data has been passed to the LTC.
 * It will wait for LTC to finish hashing and then copy the data out of 
 * context back into user-provided buffer. Buffer has to be large enough
 * to contain the resulting hash. Calling this function will free up 
 * LTC for another command.
 * @param hash address of buffer where hash has to be written
 * @returns true if hash has been written, false otherwise.
 */
__privileged bool ltc_sha_finish(uint8_t * hash);

SYSCALL(ltc_sha_finish, uint8_t *)

__privileged bool _ltc_pkha_execute(uint32_t command, pkha_reg_t destination);

/* Pseudoinstructions of PKHA processor */

/* A | B | E | N <- A | B | N @ sizeof(A | B | E | N) */
/** Copy data from one PKHA register into another.
 * @param destination destination register, may be either whole register or quadrant.
 * @param source source register, may be either whole register or quadrant. Register
 * E cannot be used as a source.
 * @param nsz if true then at most @ref LTC0_PKNSZ will be copied, otherwise, 
 * the size of the source register will determine amount of copied data.
 * @note Source and target cannot be the same.
 * @return true if operation succeeded, false otherwise. Possible reasons for failed copy
 * are:
 * - source register is E. E is write-only register and attempt to copy out of it would
 *   return zeroes. Attempt to do so will fail.
 * - either source or target quadrant is non-zero, when register E is target.
 *   LTC peripheral does not provide commands to copy to register E from other than 0th 
 *   quadrant.
 * - Operation-specific error. Consult the content of LTC0_ESTA_ERRID1 field to find out 
 *   more.
 */
__privileged bool ltc_mov(pkha_reg_t destination, pkha_reg_t source, bool nsz);

/* A | B | E | N <- mem @ sizeof(mem) */
/** Load PKHA register from RAM.
 * @param destination target PKHA register and segment
 * @param source source number stored in RAM
 * @returns true if copy has been performed, false otherwise 
 */
__privileged bool ltc_load(pkha_reg_t destination, const pkha_number_t * source);

/* mem <- A | B | N @ sizeof(mem) */
/** Save PKHA register into RAM.
 * @param source source PKHA register and segment (reg E cannot be copied)
 * @param destination target for number to be stored into RAM
 * @returns true if copy has been performed, false otherwise 
 * @note Register E is read protected and any attempt to read it will return
 *       zeroes. Thus this function deliberately prohibits storing this register.
 */
__privileged bool ltc_store(pkha_number_t * destination, pkha_reg_t source);

/* mem == A | B | N @ sizeof(mem) */
/** Compare PKHA register to the contents of RAM.
 * @param source source PKHA register and segment (reg E cannot be copied)
 * @param destination target for number to be compared with in RAM
 * @returns true if number in RAM matches number in PKHA register, false otherwise 
 * @note Register E is read protected and any attempt to read it will return
 *       zeroes. Thus this function deliberately returns false upon an attempt
 *       to compare it with RAM.
 */
__privileged bool ltc_compare(pkha_reg_t source, const pkha_number_t * destination);

/** Perform ECDSA signing.
 * @param curve EC curve parameters used (Gx, Gy, a, b, q)
 * @param input signing input used (message hash, random nonce, private key)
 * @param output resulting signature (r, s)
 * @returns LTC_OK if signature has been generated successfully. 
 *          May return LTC_BadRandomValue if random nonce provided results in 
 *          point in infinity. Get another random nonce and retry. Return value
 *          LTC_Error means that LTC operation failed. LTC peripheral must be 
 *          reset to continue.
 */
__privileged ltc_pkha_result_t ltc_pkha_sign(
                    const pkha_curve_t * curve, /* curve parameters Cx,Cy,a,b,p */
                    const pkha_sign_input_t * input, /* private key, random value, message hash */
                    pkha_signature_t * output /* signature (r, s) */
                   );

SYSCALL(ltc_pkha_sign, const pkha_curve_t *, const pkha_sign_input_t *, pkha_signature_t *)

/** Perform ECDSA signature verification.
 * @param curve EC curve parameters used (Gx, Gy, a, b, p, q)
 * @param input verification input used (message hash, public key)
 * @param signature signature to verify (r,s)
 * @returns LTC_SignatureValid if signature verification proven that signature 
 *          matches the input. LTC_SignatureInvalid is returned it signature does not 
 *          match the input (hash and/or public key donesn't match). If LTC_Error is 
 *          returned then LTC operation failed and LTC peripheral has to be reset to
 *          continue.
 */
__privileged ltc_pkha_result_t ltc_pkha_verify(
                                            const pkha_curve_t * curve,
                                            const pkha_verify_input_t * input,
                                            const pkha_signature_t * signature
                                        );

SYSCALL(ltc_pkha_verify, const pkha_curve_t *, const pkha_verify_input_t *, const pkha_signature_t *)

/** Validate if public key provide is valid.
 * @param curve curve used to check signatures
 * @param public_key public key to check for validity
 * @return LTC_PublicKeyValid if key is a valid key for verifying
 * signatures on given curve. LTC_PublicKeyInvalid if key is either invalid
 * or not usable with given curve. LTC_Error if LTC peripheral returned
 * error during key validation.
 */

__privileged ltc_pkha_result_t ltc_pkha_validate_publickey(
            const pkha_curve_t * curve,
            const pkha_verify_input_t * public_key
);

SYSCALL(ltc_pkha_validate_publickey, const pkha_curve_t *, const pkha_verify_input_t *)
