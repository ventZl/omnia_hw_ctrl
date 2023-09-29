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

#define LTC_PKHA_FUNC_COPY  (0b10000)

#define LTC_PKHA_FUNC_ADD   (0x00002)
#define LTC_PKHA_FUNC_SUB_1 (0x00003)
#define LTC_PKHA_FUNC_SUB_2 (0x00004)
#define LTC_PKHA_FUNC_MUL   (0x00405)
#define LTC_PKHA_FUNC_EXP   (0x00406)
#define LTC_PKHA_FUNC_AMODN (0x00007)
#define LTC_PKHA_FUNC_INV   (0x00008)
#define LTC_PKHA_FUNC_R2    (0x0000C)
#define LTC_PKHA_FUNC_GCD   (0x0000E)
#define LTC_PKHA_FUNC_PRIME (0x0000F)

#define LTC_PKHA_FUNC_ECC_MOD_ADD (0x00009)
#define LTC_PKHA_FUNC_ECC_MOD_DBL (0x0000A)
#define LTC_PKHA_FUNC_ECC_MOD_MUL (0x0040B)

#define LTC_PKHA_DEST_B     (0x00100)

/** Initialize the LTC peripheral.
 * This will enable clock to the LTC peripheral.
 */

static inline __privileged void ltc_init(void)
{
    clk_config(LTC_Slot, 1);

    /* Reset all internal logic, we might reinitialize previously used LTC */
    LTC0_COM = LTC0_COM_ALL;

#ifdef LTC_USE_INTERRUPTS
    /* Enable interrupts */
    nvic_enable_irq_with_prio(LTC0_IRQn, 2);
#endif
}

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

static inline __privileged bool ltc_sha_error()
{
    return (BME_BITFIELD(LTC0_STA, LTC0_STA_EI));
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
static inline __privileged void ltc_sha_start(ltc_sha_mode_t mode, uint32_t length)
{
    /* Nuke everything */
    LTC0_COM = LTC0_COM_ALL;
    uint32_t modeAs = 0;
    if (length <= 64)
    {
        /* Total length is less than 64 bytes, so we need to instruct LTC 
         * to do the padding.
         */
        modeAs = LTC0_MD_AS_INIT_FIN;
    }
    else
    {
        modeAs = LTC0_MD_AS_INIT;
    }
    /* This guy here has to be written in one access. Both MD and AS fields
     * need to be written at once. Apparently AS field updates are ever only
     * honored if MD field is written into as well. If only AS field is updated,
     * the outcome won't be as expected.
     */
    LTC0_MD = mode | modeAs;

    /* Byte swap inputs and outputs. LTC native endianess is different than
     * that of the CPU. */
    LTC0_CTL |= LTC0_CTL_COS | LTC0_CTL_CIS | LTC0_CTL_KOS | LTC0_CTL_KIS | LTC0_CTL_OFS | LTC0_CTL_IFS;
}

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
static inline __privileged bool ltc_sha_data(const uint8_t * data, uint16_t length)
{
    /* Check the context. If it is empty, do nothing as the state has been
     * pre-set by call to ltc_sha_init(). If state is non-empty, then evaluate
     * data length and update the state accordingly.
     */
    uint32_t mode = LTC0_MD & LTC0_MD_ALG_MASK;
    uint32_t context_size = ltc_hash_size(mode) / 4;
    uint32_t modeAs = 0;

    if (context_size == 0 || ltc_sha_error())
    {
        /* Unsupported hash algorithm or LTC is not in hashing mode at all. */
        return false;
    }
    uint64_t context_ds = ((uint64_t) LTC0_CTX(context_size)) << 32 | (uint64_t) LTC0_CTX(context_size + 1);
    if (context_ds != 0)
    {
        if (length == 64)
        {
            modeAs = LTC0_MD_AS_UPDATE;
        }
        else
        {
            modeAs = LTC0_MD_AS_FINALIZE;
        }

        BME_BITFIELD(LTC0_STA, LTC0_STA_DI) = LTC0_STA_DI;
        /* Clear mode and data size. Data size is not automatically
         * cleared when mode is changed, so the HASH peripheral expects
         * more data to be processed than reality.
         */
        LTC0_CW = LTC0_CW_CM | LTC0_CW_CDS;
        LTC0_MD = mode | modeAs;
    }
    /* alias data as 32-bit quantities */
    const uint32_t * data32 = (const uint32_t *) data;
    uint32_t length32 = length / 4;
    if (length % 4 != 0)
    {
        length32++;
    }

    LTC0_DS = length;

    for (unsigned q = 0; q < length32; ++q)
    {
        while(ltc_ififo_busy()) nop();
        LTC0_IFIFO = data32[q];
    }

    return !ltc_sha_error();
}

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
static inline __privileged bool ltc_sha_finish(uint8_t * hash)
{
    volatile uint32_t out_size = 0;
    /* Alias hash output to be 32-bit quantities. */
    uint32_t * hash32 = (uint32_t *) hash;

    /* Determine amount of context bytes to be read out.
     * Context can only be read as 32-bit quantities.
     */
    uint32_t ltc0_md = LTC0_MD & LTC0_MD_ALG_MASK;
    out_size = ltc_hash_size(ltc0_md) / 4;
    if (out_size == 0 || ltc_sha_error())
    {
        return false;
    }

    while (!ltc_sha_done()) nop();

    for (unsigned q = 0; q < out_size; ++q)
    {
        hash32[q] = LTC0_CTX(q);
    }

    BME_BITFIELD(LTC0_STA, LTC0_STA_DI) = LTC0_STA_DI;

    return !ltc_sha_error();
}

static inline bool _ltc_pkha_execute(uint32_t command)
{
    LTC0_MDPK = command;

    while (!ltc_sha_done())
    {
        if (ltc_sha_error())
            return false;
    }

    BME_BITFIELD(LTC0_STA, LTC0_STA_DI) = LTC0_STA_DI;

    return true;
}
/* Pseudoinstructions of PKHA processor */

/* B | A <- (A + B) mod N */
/** Modular addition.
 * @param destination output register; may only be A0 or B0 register
 * @returns true if addition was performed, false if it failed or 
 * the input is invalid.
 */
static inline __privileged bool ltc_mod_add(pkha_reg_t destination)
{
    uint32_t command = LTC_PKHA_FUNC_ADD;
    /* Validate destination argument */
    if (destination == B0)
    {
        command |= LTC_PKHA_DEST_B;
    }
    else 
    {
        if (destination != A0)
        {
            return false;
        }
    }

    return false;
}

/* B | A <- (A - B) mod N or */
/* B | A <- (B - A) mod N */
/** Modular subtraction.
 * @param destination output register; may only be A0 or B0 register
 * @param sub_1 minuend; may only be A0 or B0 register
 * @param sub_2 subtrahend; may only be A0 or B0 register
 * @returns true if subtraction was performed, false if it failed or 
 * the input is invalid.
 */
static inline __privileged bool ltc_mod_sub(pkha_reg_t destination, pkha_reg_t sub_1, pkha_reg_t sub_2)
{
    uint32_t command = 0;
    if (sub_1 == A0 && sub_2 == B0)
    {
        command = LTC_PKHA_FUNC_SUB_1;
    }
    else {
        if (sub_1 == B0 && sub_2 == A0)
        {
            command = LTC_PKHA_FUNC_SUB_2;
        }
        else
        {
            return false;
        }
    }

    /* Validate destination argument */
    if (destination == B0)
    {
        command |= LTC_PKHA_DEST_B;
    }
    else 
    {
        if (destination != A0)
        {
            return false;
        }
    }

    return _ltc_pkha_execute(command);
}

/* B | A <- (A * B) mod N */
/** Modular multiplication.
 * This call performs timing equalized variant of modular multiplication.
 * @param destination output register; may only be A0 or B0 register
 * @returns true if multiplication was performed, false if it failed or 
 * the input is invalid.
 */
static inline __privileged bool ltc_mod_mul(pkha_reg_t destination)
{
    uint32_t command = LTC_PKHA_FUNC_MUL;
    /* Validate destination argument */
    if (destination == B0)
    {
        command |= LTC_PKHA_DEST_B;
    }
    else 
    {
        if (destination != A0)
        {
            return false;
        }
    }

    return _ltc_pkha_execute(command);
}


/* B | A <- (A ^ E) mod N */
static inline __privileged bool ltc_mod_exp(pkha_reg_t destination)
{
    uint32_t command = LTC_PKHA_FUNC_EXP;
    /* Validate destination argument */
    if (destination == B0)
    {
        command |= LTC_PKHA_DEST_B;
    }
    else 
    {
        if (destination != A0)
        {
            return false;
        }
    }

    return _ltc_pkha_execute(command);
}


/* B | A <- A mod N */
/** Modulo.
 * @param destination output register; may only be A0 or B0 register
 * @returns true if modulo was performed, false if it failed or 
 * the input is invalid.
 */
static inline __privileged bool ltc_mod_amodn(pkha_reg_t destination)
{
    uint32_t command = LTC_PKHA_FUNC_AMODN;
    /* Validate destination argument */
    if (destination == B0)
    {
        command |= LTC_PKHA_DEST_B;
    }
    else 
    {
        if (destination != A0)
        {
            return false;
        }
    }

    return _ltc_pkha_execute(command);
}


/* B | A <- A^-1 mod N */
/** Modular inversion.
 * @param destination output register; may only be A0 or B0 register
 * @returns true if inversion was performed, false if it failed or 
 * the input is invalid.
 */
static inline __privileged bool ltc_mod_inv(pkha_reg_t destination)
{
    uint32_t command = LTC_PKHA_FUNC_INV;
    /* Validate destination argument */
    if (destination == B0)
    {
        command |= LTC_PKHA_DEST_B;
    }
    else 
    {
        if (destination != A0)
        {
            return false;
        }
    }

    return _ltc_pkha_execute(command);
}


/* B | A <- R2(N) */
static inline __privileged bool ltc_mod_r2(pkha_reg_t destination)
{
    uint32_t command = LTC_PKHA_FUNC_R2;
    /* Validate destination argument */
    if (destination == B0)
    {
        command |= LTC_PKHA_DEST_B;
    }
    else 
    {
        if (destination != A0)
        {
            return false;
        }
    }

    return _ltc_pkha_execute(command);
}


/* B | A <- GCD(A, N) */
/** Modular inversion.
 * @param destination output register; may only be A0 or B0 register
 * @returns true if inversion was performed, false if it failed or 
 * the input is invalid.
 */
static inline __privileged bool ltc_mod_gcd(pkha_reg_t destination)
{
    uint32_t command = LTC_PKHA_FUNC_GCD;
    /* Validate destination argument */
    if (destination == B0)
    {
        command |= LTC_PKHA_DEST_B;
    }
    else 
    {
        if (destination != A0)
        {
            return false;
        }
    }

    return _ltc_pkha_execute(command);
}


/* B | A <- is_prime(N, A, B) */
/** Modular inversion.
 * @param destination output register; may only be A0 or B0 register
 * @returns true if inversion was performed, false if it failed or 
 * the input is invalid.
 */
static inline __privileged bool ltc_prime_test(pkha_reg_t destination)
{
    uint32_t command = LTC_PKHA_FUNC_PRIME;
    /* Validate destination argument */
    if (destination == B0)
    {
        command |= LTC_PKHA_DEST_B;
    }
    else 
    {
        if (destination != A0)
        {
            return false;
        }
    }

    return _ltc_pkha_execute(command);
}


/* [B1, B2] | [A0, A1] <- [A0, A1] + [B1, B2] @ (N, A3, B0) */
/** Modular inversion.
 * @param destination output register; may only be A0 or B0 register
 * @returns true if inversion was performed, false if it failed or 
 * the input is invalid.
 */
static inline __privileged bool ltc_ecc_mod_add(pkha_reg_t destination)
{
    uint32_t command = LTC_PKHA_FUNC_ECC_MOD_ADD;
    /* Validate destination argument */
    if (destination == B0)
    {
        command |= LTC_PKHA_DEST_B;
    }
    else 
    {
        if (destination != A0)
        {
            return false;
        }
    }

    return _ltc_pkha_execute(command);
}


/* [B1, B2] | [A0, A1] <- [B1, B2] + [B1, B2] @ (N, A3, B0) */
/** Modular inversion.
 * @param destination output register; may only be A0 or B0 register
 * @returns true if inversion was performed, false if it failed or 
 * the input is invalid.
 */
static inline __privileged bool ltc_ecc_mod_dbl(pkha_reg_t destination)
{
    uint32_t command = LTC_PKHA_FUNC_ECC_MOD_DBL;
    /* Validate destination argument */
    if (destination == B0)
    {
        command |= LTC_PKHA_DEST_B;
    }
    else 
    {
        if (destination != A0)
        {
            return false;
        }
    }

    return _ltc_pkha_execute(command);
}


/* [B1, B2] | [A0, A1] <- E x [A0, A] @ (N, A3, B0) */
/** Modular inversion.
 * @param destination output register; may only be A0 or B0 register
 * @returns true if inversion was performed, false if it failed or 
 * the input is invalid.
 */
static inline __privileged bool ltc_ecc_mod_mul(pkha_reg_t destination)
{
    uint32_t command = LTC_PKHA_FUNC_ECC_MOD_MUL;
    /* Validate destination argument */
    if (destination == B0)
    {
        command |= LTC_PKHA_DEST_B;
    }
    else 
    {
        if (destination != A0)
        {
            return false;
        }
    }

    return _ltc_pkha_execute(command);
}


/* [B1, B2] | [A0, A1] <- [A0, A1] + [B1, B2] @ (N, A3, B0) */
static inline __privileged bool ltc_ecc_f2m_add(pkha_reg_t destination)
{
    uint32_t command = 0;
    /* Validate destination argument */
    if (destination == B0)
    {
        command |= LTC_PKHA_DEST_B;
    }
    else 
    {
        if (destination != A0)
        {
            return false;
        }
    }

    return _ltc_pkha_execute(command);
}


/* [B1, B2] | [A0, A1] <- [B1, B2] + [B1, B2] @ (N, A3, B0) */
static inline __privileged bool ltc_ecc_f2m_dbl(pkha_reg_t destination)
{
    uint32_t command = 0;
    /* Validate destination argument */
    if (destination == B0)
    {
        command |= LTC_PKHA_DEST_B;
    }
    else 
    {
        if (destination != A0)
        {
            return false;
        }
    }

    return _ltc_pkha_execute(command);
}


/* [B1, B2] | [A0, A1] <- E x [A0, A] @ (N, A3, B0) */
static inline __privileged bool ltc_ecc_f2m_mul(pkha_reg_t destination)
{
    uint32_t command = 0;
    /* Validate destination argument */
    if (destination == B0)
    {
        command |= LTC_PKHA_DEST_B;
    }
    else 
    {
        if (destination != A0)
        {
            return false;
        }
    }

    return _ltc_pkha_execute(command);
}


static inline __privileged bool ltc_clear(pkha_reg_t destination)
{
    (void) destination;
    return false;
}

/* A | B | E | N <- A | B | N @ sizeof(A | B | E | N) */
/** Copy data from one PKHA register into another.
 * @param destination destination register, may be either whole register or quadrant.
 * @param source source register, may be either whole register or quadrant. Register
 * E cannot be used as a source.
 * @param nsz if true then at most @ref LTC0_PKNSZ will be copied, otherwise, 
 * the size of the source register will determine amount of copied data.
 * @note Source and target cannot be the same.
 * @return true if operation succeeded, false otherwise.
 */
static inline __privileged bool ltc_mov(pkha_reg_t destination, pkha_reg_t source, bool nsz)
{
    if (source == destination || source == E)
    {
        return false;
    }
    uint32_t src_reg = ((uint32_t) source) >> 3;
    uint32_t dst_reg = ((uint32_t) destination) >> 3;

    uint32_t src_segment = ((uint32_t) source) & 3;
    uint32_t dst_segment = ((uint32_t) destination) & 3;

    if (destination == E && dst_segment != 0)
    {
        return false;
    }

    uint32_t command = 
        (src_reg << 17) | (dst_reg << 10) | (src_segment << 8) | (dst_segment << 6) | LTC_PKHA_FUNC_COPY;

    /* COPY source-size has function 0b10001 */
    if (!nsz)
    {
        command |= 1;
    }
    
    LTC0_MDPK = command;
    while (!ltc_sha_done())
    {
        if (ltc_sha_error())
            return false;
    }

    BME_BITFIELD(LTC0_STA, LTC0_STA_DI) = LTC0_STA_DI;

    return true;
}

/* A | B | E | N <- mem @ sizeof(mem) */
/** Load PKHA register from RAM.
 * TODO: This will probably need some kind of byteswap
 * @param destination target PKHA register and segment
 * @param source source RAM buffer containing the source data
 * @param size size of the source data
 * @returns true if copy has been performed, false otherwise 
 */
static inline __privileged bool ltc_load(pkha_reg_t destination, const uint32_t * source, unsigned size)
{
    uint32_t dst_reg = ((uint32_t) destination) >> 3;
    uint32_t dst_segment = ((uint32_t) destination) & 3;

    if (dst_segment > 0)
    {
        if (dst_reg == _REG_E)
            return false;

        if (size > 64)
            return false;
    } else {
        if (size > 256)
            return false;
    }
   
    uint32_t size32 = size / 4;
    if (size % 4 != 0)
    {
        size32++;
    }

    switch (dst_reg)
    {
        case _REG_A:
            {
                LTC0_PKASZ = size;
                for (unsigned q = 0; q < size32; ++q)
                {
                    LTC0_PKHA_A(dst_segment, q) = source[q];
                }
            }
            return true;

        case _REG_B:
            {
                LTC0_PKBSZ = size;
                for (unsigned q = 0; q < size32; ++q)
                {
                    LTC0_PKHA_B(dst_segment, q) = source[q];
                }
            }
            return true;

        case _REG_N:
            {
                LTC0_PKNSZ = size;
                for (unsigned q = 0; q < size32; ++q)
                {
                    LTC0_PKHA_N(dst_segment, q) = source[q];
                }
            }
            return true;

        case _REG_E:
            {
                LTC0_PKESZ = size;
                for (unsigned q = 0; q < size32; ++q)
                {
                    LTC0_PKHA_E(q) = source[q];
                }
            }
            return true;

        default:
            return false;
    }
}

/* mem <- A | B | E N @ sizeof(mem) */
/** Load PKHA register from RAM.
 * @param source source PKHA register and segment
 * @param destination target RAM buffer containing the source data
 * @param size buffer where data size will be written
 * @returns true if copy has been performed, false otherwise 
 */
bool ltc_store(uint32_t * destination, unsigned * size, pkha_reg_t source);

/** Perform ECDSA signature.
 * @param Nonce ???
 * @param r ???
 * @param Gx x coordinate of the base point G
 * @param Gy y coordinate of the base point G
 * @param q ???
 * @param a curve parameter a
 * @param b curve parameter b
 * @param f message hash (???)
 * @param d message signature
 */
static inline __privileged bool ltc_phka_sign(const uint32_t * Nonce, uint16_t Nonce_size,
                    const uint32_t * r, uint16_t r_size,
                    const uint32_t * Gx, int Gx_size,
                    const uint32_t * Gy, int Gy_size,
                    const uint32_t * q, int q_size,
                    const uint32_t * a, int a_size,
                    const uint32_t * b, int b_size, 
                    const uint32_t * s, 
                    const uint32_t * f, int f_size,
                    uint32_t * d,
                    unsigned * d_size)
{
    uint32_t tmp_c[16];
    uint32_t tmp_h[16];
    unsigned sz_c;
    unsigned sz_h;

    ltc_load(A0, Nonce, Nonce_size);
    ltc_load(N0, r, r_size);
    /* u = Nonce mod r */
    /* A0 <- A0 mod N */
    ltc_mod_amodn(A0);
    /* h = 1/u mod r */
    ltc_mov(N2, A0, false);
    ltc_mod_inv(B0);
    /* V = u * G  (public key for u) */
    ltc_store(tmp_h, &sz_h, B0);
    ltc_load(N0, q, q_size);
    ltc_load(A3, a, a_size);
    ltc_load(A0, Gx, Gx_size);
    ltc_load(A1, Gy, Gy_size);
    ltc_mov(B0, N2, false);
    ltc_mov(E, B0, false);
    ltc_load(B0, b, b_size);
    ltc_ecc_mod_mul(B0);
    ltc_mov(A0, B1, false);
    ltc_load(N0, r, r_size);
    /* c = Vx mod r */
    ltc_mod_amodn(B0);
    ltc_store(tmp_c, &sz_c, B0);
    ltc_load(A0, s, r_size);
    /* (s * c) mod r */
    /* B0 <- A0 * B0 mod R */
    ltc_mod_mul(B0);
    ltc_load(A0, f, f_size);
    /* B0 <- A0 + B0 mod R */
    /* (f + (s * c)) mod r */
    ltc_mod_add(B0);
    ltc_load(A0, tmp_h, sz_h);
    /* d = (h * (f + s*c)) mod r */
    /* B0 <- A0 * B0 mod R */
    ltc_mod_mul(B0);
    ltc_store(d, d_size, B0);

    return true;
}

static inline __privileged bool ltc_phka_verify()
{
    return false;

}

SYSCALL(ltc_sha_finish, uint8_t *)
