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
    pkha_number_t n;    /* n - order of [Gx, Gy] */
} pkha_curve_t;

/* This struct only exist to minimize amount of 
 * ECDSA-related number of function arguments
 */
typedef struct {
    const pkha_number_t random_k; /* k - random value */
    const pkha_number_t pkey; /* private key? */
    const pkha_number_t hash; /* z - message hash */
} pkha_input_t;

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

static inline bool _ltc_pkha_execute(uint32_t command, pkha_reg_t destination)
{
    /* Validate destination argument */
    if (destination == A0)
    {
        command |= LTC_PKHA_DEST_A;
    }
    else 
    {
        if (destination != B0)
        {
            return false;
        }
    }

    debug("MDPK = %06x\n", command);
    LTC0_MDPK = command;

    while (!ltc_sha_done())
    {
        if (ltc_sha_error())
        {
            debug("PKHA error: %x\n", BME_BITFIELD(LTC0_ESTA, LTC0_ESTA_ERRID1_MASK));
            return false;
        }
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
    if (destination == A0)
    {
        command |= LTC_PKHA_DEST_A;
    }
    else 
    {
        if (destination != B0)
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

    return _ltc_pkha_execute(command, destination);
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

    return _ltc_pkha_execute(command, destination);
}


/* B | A <- (A ^ E) mod N */
static inline __privileged bool ltc_mod_exp(pkha_reg_t destination)
{
    uint32_t command = LTC_PKHA_FUNC_EXP;

    return _ltc_pkha_execute(command, destination);
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
    return _ltc_pkha_execute(command, destination);
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

    return _ltc_pkha_execute(command, destination);
}


/* B | A <- R2(N) */
static inline __privileged bool ltc_mod_r2(pkha_reg_t destination)
{
    uint32_t command = LTC_PKHA_FUNC_R2;
    
    return _ltc_pkha_execute(command, destination);
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

    return _ltc_pkha_execute(command, destination);
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

    return _ltc_pkha_execute(command, destination);
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

    return _ltc_pkha_execute(command, destination);
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

    return _ltc_pkha_execute(command, destination);
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

    return _ltc_pkha_execute(command, destination);
}


/* [B1, B2] | [A0, A1] <- [A0, A1] + [B1, B2] @ (N, A3, B0) */
static inline __privileged bool ltc_ecc_f2m_add(pkha_reg_t destination)
{
    uint32_t command = 0;

    return _ltc_pkha_execute(command, destination);
}


/* [B1, B2] | [A0, A1] <- [B1, B2] + [B1, B2] @ (N, A3, B0) */
static inline __privileged bool ltc_ecc_f2m_dbl(pkha_reg_t destination)
{
    uint32_t command = 0;

    return _ltc_pkha_execute(command, destination);
}


/* [B1, B2] | [A0, A1] <- E x [A0, A] @ (N, A3, B0) */
static inline __privileged bool ltc_ecc_f2m_mul(pkha_reg_t destination)
{
    uint32_t command = 0;

    return _ltc_pkha_execute(command, destination);
}


static inline __privileged bool ltc_clear(pkha_reg_t reg)
{
    uint32_t clr_reg = ((uint32_t) reg) >> 3;
    uint32_t clr_segment = ((uint32_t) reg) & 3;

    if (clr_reg == _REG_N)
    {
        if (clr_segment > 0)
        {
            return false;
        }
    }

    uint32_t command = (1 << (19 - clr_reg)) | LTC_PKHA_FUNC_CLEAN;
    /* HACK! HACK! HACK! here we pass B0 so _ltc_pkha_execute won't mess 
     * with the command passed.
     */
    return _ltc_pkha_execute(command, B0);
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
        debug("Implausible source!\n");
        return false;
    }
    uint32_t src_reg = ((uint32_t) source) >> 3;
    uint32_t dst_reg = ((uint32_t) destination) >> 3;

    uint32_t src_segment = ((uint32_t) source) & 3;
    uint32_t dst_segment = ((uint32_t) destination) & 3;

    if (destination == E && dst_segment != 0)
    {
        debug("Invalid quadrant!\n");
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
        {
            debug("LTC error %d copying!\n", BME_BITFIELD(LTC0_ESTA, LTC0_ESTA_ERRID1_MASK));
            return false;
        }
    }

    BME_BITFIELD(LTC0_STA, LTC0_STA_DI) = LTC0_STA_DI;

    return true;
}

/* A | B | E | N <- mem @ sizeof(mem) */
/** Load PKHA register from RAM.
 * @param destination target PKHA register and segment
 * @param source source number stored in RAM
 * @returns true if copy has been performed, false otherwise 
 */
static inline __privileged bool ltc_load(pkha_reg_t destination, const pkha_number_t * source)
{
    uint32_t dst_reg = ((uint32_t) destination) >> 3;
    uint32_t dst_segment = ((uint32_t) destination) & 3;

    if (dst_segment > 0)
    {
        if (dst_reg == _REG_E)
            return false;

        if (source->length > 64)
            return false;
    } else {
        if (source->length > 256)
            return false;
    }
   
    uint32_t length32 = source->length / 4;
    if (source->length % 4 != 0)
    {
        length32++;
    }

    switch (dst_reg)
    {
        case _REG_A:
            LTC0_PKASZ = source->length;
            break;
        case _REG_B:
            LTC0_PKBSZ = source->length;
            break;
        case _REG_E:
            LTC0_PKESZ = source->length;
            break;
        case _REG_N:
            LTC0_PKNSZ = source->length;
            break;
        default:
            /* Invalid register specified */
            return false;
    }

    for (unsigned q = 0; q < length32; ++q)
    {
        uint32_t tmp_data = ((uint32_t *) source->number)[q];
        switch (dst_reg)
        {
            case _REG_A:
                LTC0_PKHA_A(dst_segment, q) = tmp_data;
                break;

            case _REG_B:
                LTC0_PKHA_B(dst_segment, q) = tmp_data;
                break;

            case _REG_E:
                LTC0_PKHA_E(q) = tmp_data;
                break;

            case _REG_N:
                LTC0_PKHA_N(dst_segment, q) = tmp_data;
                break;
        }
    }

    return true;
}

/* mem <- A | B | N @ sizeof(mem) */
/** Save PKHA register into RAM.
 * @param source source PKHA register and segment (reg E cannot be copied)
 * @param destination target for number to be stored into RAM
 * @returns true if copy has been performed, false otherwise 
 * @note Register E is read protected and any attempt to read it will return
 *       zeroes. Thus this function deliberately prohibits storing this register.
 */
static inline bool ltc_store(pkha_number_t * destination, pkha_reg_t source)
{
    uint32_t src_reg = ((uint32_t) source) >> 3;
    uint32_t src_segment = ((uint32_t) source) & 3;

    if (src_reg == _REG_E)
    {
        return false;
    }

    switch(src_reg)
    {
        case _REG_A:
            destination->length = LTC0_PKASZ;
            break;
        case _REG_B:
            destination->length = LTC0_PKBSZ;
            break;
        case _REG_N:
            destination->length = LTC0_PKNSZ;
            break;
        default:
            return false;
    }

    uint32_t length32 = destination->length / 4;
    if (destination->length % 4 != 0)
    {
        length32++;
    }

    for (unsigned q = 0; q < length32; ++q)
    {
        uint32_t tmp_data = 0;
        switch (src_reg)
        {
            case _REG_A:
                tmp_data = LTC0_PKHA_A(src_segment, q);
                break;

            case _REG_B:
                tmp_data = LTC0_PKHA_B(src_segment, q);
                break;

            case _REG_N:
                tmp_data = LTC0_PKHA_N(src_segment, q);
                break;
        }
        ((uint32_t *) destination->number)[q] = tmp_data;
    }

    return true;
}

/* Dumps LTC register.
 */
static inline void tmp_ltc_dump_register(pkha_reg_t reg, const char * what)
{
    uint32_t src_reg = ((uint32_t) reg) >> 3;
    uint32_t src_segment = ((uint32_t) reg) & 3;
    uint32_t length;

    if (src_reg == _REG_E)
    {
        debug("%s (E):\n  ---- this register is write-only and cannot be dumped! ----\n", what);
        return;
    }

    switch(src_reg)
    {
        case _REG_A:
            length = LTC0_PKASZ;
            debug("%s (A%d):\n ", what, src_segment);
            break;
        case _REG_B:
            length = LTC0_PKBSZ;
            debug("%s (B%d):\n ", what, src_segment);
            break;
        case _REG_N:
            length = LTC0_PKNSZ;
            debug("%s (N):\n ", what, src_segment);
            break;
        default:
            return;
    }

    for (int q = length - 1; q >= 0; --q)
    {
        uint32_t data = 0;

        switch (src_reg)
        {
        case _REG_A:
            data = LTC0_PKHA_A(src_segment, q / 4);
            break;

        case _REG_B:
            data = LTC0_PKHA_B(src_segment, q / 4);
            break;

        case _REG_N:
            data = LTC0_PKHA_N(src_segment, q / 4);
            break;

        default:
            return;
        }

        uint32_t byte = ((uint8_t *)&data)[q % 4];

        debug("%02x ", byte);
        if (q % 4 == 0 && q != 0)
        {
            debug("- ");
        }

    }
    debug("\n");
}


/** Perform ECDSA signature.
 * @param curve EC curve parameters used (Gx, Gy, a, b, q)
 * @param input signing input used (message hash, random nonce, private key)
 * @param output resulting signature (r, s)
 */
static inline __privileged bool ltc_pkha_sign(
                    const pkha_curve_t * curve, /* curve parameters Cx,Cy,a,b,p */
                    const pkha_input_t * input, /* private key, random value, message hash */
                    pkha_signature_t * output /* signature (r, s) */
                   )
{
    pkha_number_t tmp_h; /* a.k.a k^-1 - modular inverse of k */

    /* A0 <- A0 mod N */
    /* u = Nonce mod r */
    ltc_load(A0, &input->random_k);
    tmp_ltc_dump_register(A0, "random_k");
    ltc_load(N0, &curve->n);
    tmp_ltc_dump_register(N0, "modulus");
    ltc_mod_amodn(A0);
    tmp_ltc_dump_register(A0, "ks");

    /* h = 1/u mod r */
    ltc_mov(N2, A0, false);
    tmp_ltc_dump_register(N0, "modulus");
    ltc_mod_inv(B0);
//    tmp_ltc_dump_register(B0, "1/nonce mod r");
    tmp_ltc_dump_register(B0, "h");

    /* V = u * G  (public key for u) */
    ltc_store(&tmp_h, B0);
    ltc_clear(B0);
    ltc_clear(A0);
    ltc_clear(E);

    ltc_mov(B0, N2, false);
    tmp_ltc_dump_register(B0, "ks");

    ltc_clear(N0);
    ltc_load(N0, &(curve->n));
    ltc_load(A3, &(curve->a));
    ltc_load(A0, &(curve->Gx));
    ltc_load(A1, &(curve->Gy));

//    tmp_ltc_dump_register(B0, "h");
    debug("V = u * G\nInputs:\n");

    ltc_mov(E, B0, false);

    ltc_load(B0, &(curve->b));
    tmp_ltc_dump_register(N0, "modulus");
    tmp_ltc_dump_register(A3, "curve a");
    tmp_ltc_dump_register(B0, "curve b");
    tmp_ltc_dump_register(A0, "Gx");
    tmp_ltc_dump_register(A1, "Gy");

    ltc_ecc_mod_mul(B0);
    debug("Outputs:\n");
    tmp_ltc_dump_register(B1, "r");

    /* c = Vx mod r */
    ltc_mov(A0, B1, false);
    ltc_load(N0, &curve->n);
    ltc_mod_amodn(B0);
    tmp_ltc_dump_register(B0, "r");

    /* (s * c) mod r */
    /* B0 <- A0 * B0 mod R */
    ltc_store(&output->c, B0);
    ltc_load(A0, &input->pkey);
    tmp_ltc_dump_register(A0, "key");
    ltc_mod_mul(B0);

    /* B0 <- A0 + B0 mod R */
    /* (f + (s * c)) mod r */
    ltc_load(A0, &input->hash);
    tmp_ltc_dump_register(A0, "hash");
    ltc_mod_add(B0);

    /* d = (h * (f + s*c)) mod r */
    /* B0 <- A0 * B0 mod R */
    ltc_load(A0, &tmp_h);
    ltc_mod_mul(B0);
    tmp_ltc_dump_register(B0, "s");

    ltc_store(&output->d, B0);

    return true;
}

SYSCALL(ltc_pkha_sign, const pkha_curve_t *, const pkha_input_t *, pkha_signature_t *)

static inline __privileged bool ltc_phka_verify()
{
    return false;

}

SYSCALL(ltc_sha_finish, uint8_t *)
