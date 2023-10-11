#include "ltc.h"

__privileged void ltc_init(void)
{
    clk_config(LTC_Slot, 1);

    /* Reset all internal logic, we might reinitialize previously used LTC */
    LTC0_COM = LTC0_COM_ALL;

#ifdef LTC_USE_INTERRUPTS
    /* Enable interrupts */
    nvic_enable_irq_with_prio(LTC0_IRQn, 2);
#endif
}

__privileged void ltc_sha_start(ltc_sha_mode_t mode, uint32_t length)
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

__privileged bool ltc_sha_data(const uint8_t * data, uint16_t length)
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

__privileged bool ltc_sha_finish(uint8_t * hash)
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

/* Dumps LTC register.
 * @param reg register to be dumped
 * @param what string description of register content (e.g. key, curve a, etc.)
 */
static void tmp_ltc_dump_register(pkha_reg_t reg, const char * what)
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

/*
 * Following are functions that provide access to LTC PKHA operations in 
 * the form of pseudo-assembly. Almost all of LTC operations have implicit
 * arguments stored in pre-determined and fixed LTC registers (buffers).
 * Arithmetic operations allow to select the output register to be either
 * A (or a pair of its quadrants) or B (similarly).
 *
 * These provide low level interface to the PKHA functionality implementing
 * elliptic curve cryptography.
 *
 * As they are pseudo-assembly instructions, the code using them looks like
 * a piece of assembly code. It is strongly advised against using them directly 
 * to implement more complex pieces of code. Use wrapper functions instead.
 */

/** Modular addition.
 * Will calculate (A + B) mod N. Values are taken from A, B and N registers.
 * Result may be stored either into A or B register. Size or operation depends
 * on the size of value stored in the N register. If operands are larger than 
 * N, then the operation will fail.
 * @param destination output register; may only be A0 or B0 register
 * @returns true if addition was performed, false if it failed or 
 * the input is invalid.
 */
static inline __privileged bool _ltc_mod_add(pkha_reg_t destination)
{
    uint32_t command = LTC_PKHA_FUNC_ADD;

    return _ltc_pkha_execute(command, destination);
}

/** Modular subtraction.
 * Will calculate either (A - B) mod N or (B - A) mod N. Values are taken from 
 * A, B and N registers. Result may be stored either into A or B register. Size of 
 * operation depends on the size of value stored in the N register.
 * @param destination output register; may only be A0 or B0 register
 * @param sub_1 minuend; may only be A0 or B0 register
 * @param sub_2 subtrahend; may only be A0 or B0 register
 * @returns true if subtraction was performed, false if it failed or 
 * the input is invalid.
 */
static inline __privileged bool _ltc_mod_sub(pkha_reg_t destination, pkha_reg_t sub_1, pkha_reg_t sub_2)
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

/** Modular multiplication.
 * Will calculate (A * B) mod N. Values are taken from A, B and N registers.
 * Result may be stored either into A or B register. Size or operation depends
 * on the size of value stored in the N register. If operands are larger than 
 * N, then the operation will fail.
 * @note This call performs timing equalized variant of modular multiplication.
 * @param destination output register; may only be A0 or B0 register
 * @returns true if multiplication was performed, false if it failed or 
 * the input is invalid.
 */
static inline __privileged bool _ltc_mod_mul(pkha_reg_t destination)
{
    uint32_t command = LTC_PKHA_FUNC_MUL;

    return _ltc_pkha_execute(command, destination);
}


/** Modular exponentiation.
 * Will calculate (A ^ E) mod N. Values are taken from A, E and N registers.
 * Result may be stored either into A or B register. Size or operation depends
 * on the size of value stored in the N register. If operands are larger than 
 * N, then the operation will fail.
 * @param destination output register; may only be A0 or B0 register
 * @returns true if exponentiation was performed, false if it failed or 
 * the input is invalid.
 */
static inline __privileged bool _ltc_mod_exp(pkha_reg_t destination)
{
    uint32_t command = LTC_PKHA_FUNC_EXP;

    return _ltc_pkha_execute(command, destination);
}


/** Calculate modulo of the value.
 * Will calculate A mod N. Values are taken from A and N registers.
 * Result may be stored either into A or B register. Size of value in A register
 * may be larger than the size of the value in the N register.
 * @param destination output register; may only be A0 or B0 register
 * @returns true if modulo was performed, false if it failed or 
 * the input is invalid.
 */
static inline __privileged bool _ltc_mod_amodn(pkha_reg_t destination)
{
    uint32_t command = LTC_PKHA_FUNC_AMODN;
    return _ltc_pkha_execute(command, destination);
}


/* B | A <- A^-1 mod N */
/** Modular inversion.
 * Will calculate (A^-1) mod N. Values are taken from A and N registers.
 * Result may be stored either into A or B register. Size or operation depends
 * on the size of value stored in the N register. If operands are larger than 
 * N, then the operation will fail.
 * @param destination output register; may only be A0 or B0 register
 * @returns true if inversion was performed, false if it failed or 
 * the input is invalid.
 */
static inline __privileged bool _ltc_mod_inv(pkha_reg_t destination)
{
    uint32_t command = LTC_PKHA_FUNC_INV;

    return _ltc_pkha_execute(command, destination);
}


/* B | A <- R2(N) */
/** Calculate R2 factor.
 * Will calculate R2 factor for value N. Value is taken register N.
 * Result may be stored either into A or B register. Size or operation depends
 * on the size of value stored in the N register. 
 * @param destination output register; may only be A0 or B0 register
 * @returns true if inversion was performed, false if it failed or 
 * the input is invalid.
 */
static inline __privileged bool _ltc_mod_r2(pkha_reg_t destination)
{
    uint32_t command = LTC_PKHA_FUNC_R2;
    
    return _ltc_pkha_execute(command, destination);
}


/* B | A <- GCD(A, N) */
/** Calculate greatest common divisor of two values.
 * Will calculate greatest common divisor of A and N. Values are taken from 
 * A and N register. Size of the operation depends on the size of value 
 * stored in the N register.
 * @param destination output register; may only be A0 or B0 register
 * @returns true if divisor calculation was performed, false if it failed or 
 * the input is invalid.
 */
static inline __privileged bool _ltc_mod_gcd(pkha_reg_t destination)
{
    uint32_t command = LTC_PKHA_FUNC_GCD;

    return _ltc_pkha_execute(command, destination);
}


/* B | A <- is_prime(N, A, B) */
/** Test if value is a prime.
 * Will perform Miller-Rabin primarility test of value stored in register N.
 * Uses random seed value stored in register A to run amount of trials stored
 * in the lowest byte of register B. If register B contains value of 0, one trial 
 * will still be ran. Value in A must be less than the value of N-2 and might not
 * be zero.
 * @param destination output register; may only be A0 or B0 register
 * @returns true if inversion was performed, false if it failed or 
 * the input is invalid.
 */
static inline __privileged bool _ltc_prime_test(pkha_reg_t destination)
{
    uint32_t command = LTC_PKHA_FUNC_PRIME;

    return _ltc_pkha_execute(command, destination);
}


/** Elliptic curve point addition.
 * Will perform sum of two points on an elliptic curve. Points added have their
 * coordinates stored in [A0, A1] and [B1, B2] registers. Curve parameters are 
 * stored in A3 (a parameter) and B0 (b parameter) register. Register N contains
 * field modulus and determines the size of the operation. If any operand is larger
 * than N operation will fail. It will fail for any value of N which is longer than 
 * 64 bytes or even.
 * If A0 is chosen as result output, then resulting point is stored in [A0, A1] 
 * register pair, while pair of [B1, B2] is used for B0 chosen as the output.
 * @param destination output register; may only be A0 or B0 register
 * @returns true if addition was performed, false if it failed or 
 * the input is invalid.
 */
static inline __privileged bool _ltc_ecc_mod_add(pkha_reg_t destination)
{
    uint32_t command = LTC_PKHA_FUNC_ECC_MOD_ADD;

    return _ltc_pkha_execute(command, destination);
}


/** Elliptic curve point duplication.
 * Will perform sum of point with itself on an elliptic curve. Point added has its 
 * coordinates stored in [B1, B2] registers. Curve parameters are 
 * stored in A3 (a parameter) and B0 (b parameter) register. Register N contains
 * field modulus and determines the size of the operation. If any operand is larger
 * than N operation will fail. It will fail for any value of N which is longer than 
 * 64 bytes or even.
 * If A0 is chosen as result output, then resulting point is stored in [A0, A1] 
 * register pair, while pair of [B1, B2] is used for B0 chosen as the output.
 * @param destination output register; may only be A0 or B0 register
 * @returns true if duplication was performed, false if it failed or 
 * the input is invalid.
 */
static inline __privileged bool _ltc_ecc_mod_dbl(pkha_reg_t destination)
{
    uint32_t command = LTC_PKHA_FUNC_ECC_MOD_DBL;

    return _ltc_pkha_execute(command, destination);
}

/** Elliptic curve scalar point multiplication.
 * Will perform multiplication of scalar and point on an elliptic curve. Scalar 
 * by which the point is multiplied is stored in the E register, the point has its 
 * coordinates stored in [B1, B2] registers. Curve parameters are 
 * stored in A3 (a parameter) and B0 (b parameter) register. Register N contains
 * field modulus and determines the size of the operation. If any operand is larger
 * than N operation will fail. It will fail for any value of N which is longer than 
 * 64 bytes or even.
 * If A0 is chosen as result output, then resulting point is stored in [A0, A1] 
 * register pair, while pair of [B1, B2] is used for B0 chosen as the output.
 * @note This call performs timing equalized variant of modular multiplication.
 * @param destination output register; may only be A0 or B0 register
 * @returns true if multiplication was performed, false if it failed or 
 * the input is invalid.
 */
static inline __privileged bool _ltc_ecc_mod_mul(pkha_reg_t destination)
{
    uint32_t command = LTC_PKHA_FUNC_ECC_MOD_MUL;

    return _ltc_pkha_execute(command, destination);
}

/* Following functions form higher level API to access LTC functions.
 * They combine LTC operation with code to load the function operands.
 * This makes the code using these functions a lot less spaghetti-like 
 * and better understandable.
 */

__privileged bool ltc_mod_add(pkha_reg_t destination, 
                              const pkha_number_t * a, 
                              const pkha_number_t * b, 
                              const pkha_number_t * modulo)
{
    ltc_load(A0, a);
    ltc_load(B0, b);
    ltc_load(N0, modulo);

    return _ltc_mod_add(destination);
}

__privileged bool ltc_mod_sub(pkha_reg_t destination,
                              const pkha_number_t * a,
                              const pkha_number_t * b,
                              const pkha_number_t * modulo)
{
    ltc_load(A0, a);
    ltc_load(B0, b);
    ltc_load(N0, modulo);

    return _ltc_mod_sub(destination, A0, B0);
}

__privileged bool ltc_mod_mul(pkha_reg_t destination,
                              const pkha_number_t * a,
                              const pkha_number_t * b,
                              const pkha_number_t * modulo)
{
    ltc_load(A0, a);
    ltc_load(B0, b);
    ltc_load(N0, modulo);

    return _ltc_mod_mul(destination);
}

__privileged bool ltc_mod_exp(pkha_reg_t destination,
                              const pkha_number_t * a,
                              const pkha_number_t * e,
                              const pkha_number_t * modulo)
{
    ltc_load(A0, a);
    ltc_load(E, e);
    ltc_load(N0, modulo);

    return _ltc_mod_exp(destination);
}

__privileged bool ltc_mod_amodn(pkha_reg_t destination,
                              const pkha_number_t * a,
                              const pkha_number_t * modulo)
{
    ltc_load(A0, a);
    ltc_load(N0, modulo);

    return _ltc_mod_amodn(destination);
}

__privileged bool ltc_mod_inv(pkha_reg_t destination,
                              const pkha_number_t * a,
                              const pkha_number_t * modulo)
{
    ltc_load(A0, a);
    ltc_load(N0, modulo);

    return _ltc_mod_inv(destination);
}

__privileged bool ltc_mod_r2(pkha_reg_t destination,
                              const pkha_number_t * modulo)
{
    ltc_load(N0, modulo);

    return _ltc_mod_r2(destination);
}

__privileged bool ltc_mod_gcd(pkha_reg_t destination,
                              const pkha_number_t * a,
                              const pkha_number_t * modulo)
{
    ltc_load(A0, a);
    ltc_load(N0, modulo);

    return _ltc_mod_gcd(destination);
}

__privileged bool ltc_prime_test(pkha_reg_t destination, 
                              const pkha_number_t * seed, 
                              const pkha_number_t * trials, 
                              const pkha_number_t * candidate)
{
    ltc_load(A0, seed);
    ltc_load(B0, trials);
    ltc_load(N0, candidate);

    return _ltc_mod_add(destination);
}

__privileged bool ltc_ecc_mod_add(pkha_reg_t destination, 
                              const pkha_number_t * point1_x, 
                              const pkha_number_t * point1_y, 
                              const pkha_number_t * point2_x, 
                              const pkha_number_t * point2_y, 
                              const pkha_number_t * curve_a, 
                              const pkha_number_t * curve_b, 
                              const pkha_number_t * modulo)
{
    ltc_load(A0, point1_x);
    ltc_load(A1, point1_y);
    ltc_load(B1, point2_x);
    ltc_load(B2, point2_y);
    ltc_load(A3, curve_a);
    ltc_load(B0, curve_b);
    ltc_load(N0, modulo);

    return _ltc_ecc_mod_add(destination);
}

__privileged bool ltc_ecc_mod_dbl(pkha_reg_t destination, 
                              const pkha_number_t * point_x, 
                              const pkha_number_t * point_y, 
                              const pkha_number_t * curve_a, 
                              const pkha_number_t * curve_b, 
                              const pkha_number_t * modulo)
{
    ltc_load(B1, point_x);
    ltc_load(B2, point_y);
    ltc_load(A3, curve_a);
    ltc_load(B0, curve_b);
    ltc_load(N0, modulo);

    return _ltc_ecc_mod_dbl(destination);
}

__privileged bool ltc_ecc_mod_mul(pkha_reg_t destination, 
                              const pkha_number_t * scalar,
                              const pkha_number_t * point_x, 
                              const pkha_number_t * point_y, 
                              const pkha_number_t * curve_a, 
                              const pkha_number_t * curve_b, 
                              const pkha_number_t * modulo)
{
    ltc_load(E, scalar);
    ltc_load(A0, point_x);
    ltc_load(A1, point_y);
    ltc_load(A3, curve_a);
    ltc_load(B0, curve_b);
    ltc_load(N0, modulo);

    return _ltc_ecc_mod_mul(destination);
}



/** Clear content of register or quadrant.
 * Clears content of register or one of its quadrants. 
 * @note Register E is not divided into quadrants.
 * @param reg register to be cleared. If quadrant 0 is passed the whole register is cleared.
 * @returns true if register has been cleared, false if error occurred.
 */
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
    /* Destination B0 will pass command unmodified */
    return _ltc_pkha_execute(command, B0);
}

/** Execute LTC command and wait for completion.
 * Will execute LTC command. For commands which allow choosing the destination
 * register it allows to choose either A or B as the command output.
 * @param command value to be written into LTC0_MDPK register.
 * @param destination if command supports it, allows choosing between A or B as 
 *        command output register. Use values of A0 or B0 to select target. For other 
 *        commands use B0 as an output - will pass @ref command unmodified.
 * @returns true if operation finished without error. False is operation failed or 
 *          destination contains invalid value.
 */
__privileged bool _ltc_pkha_execute(uint32_t command, pkha_reg_t destination)
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

    LTC0_MDPK = command;

    while (!ltc_sha_done())
    {
        if (ltc_sha_error())
        {
            debug("LTC command %x error %d\n", command, BME_BITFIELD(LTC0_ESTA, LTC0_ESTA_ERRID1_MASK));
            return false;
        }
    }

    BME_BITFIELD(LTC0_STA, LTC0_STA_DI) = LTC0_STA_DI;

    return true;
}

/** Perform copy of data from register to register.
 * Will copy data from one register or its quadrant into another register or quadrant.
 * Size of the operation is determined either by the size of source or the size of 
 * the value in register N. If size of the value copied is larger than destination 
 * quadrant, it will spill into next quadrant.
 * Register E is read-only and not divided into quadrants so and LTC does not provide 
 * command for copying data from non-zero quadrant of any register into register E, 
 * so any operation targeting E register must copy from quadrant 0. Reads from register 
 * E will deliberately fail.
 * @param destination register where the data has to be copied 
 * @param source register which contains data to be copied
 * @param nsz if set to true then copying is performed on the block of size of the 
 *        value in the register N. Otherwise the operation is performed on the whole 
 *        size of the source data.
 * @returns true if copy has been performed. False if it failed or arguments are invalid.
 */
__privileged bool ltc_mov(pkha_reg_t destination, pkha_reg_t source, bool nsz)
{
    if (source == destination || source == E)
    {
        return false;
    }
    uint32_t src_reg = ((uint32_t) source) >> 3;
    uint32_t dst_reg = ((uint32_t) destination) >> 3;

    uint32_t src_segment = ((uint32_t) source) & 3;
    uint32_t dst_segment = ((uint32_t) destination) & 3;

    if (destination == E && (dst_segment != 0 || src_segment != 0))
    {
        /* There is no mapping for copying from non-zero source segment into E */
        debug("Register E does not support segments!\n");
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
            debug("Move failed with error: %d\n", BME_BITFIELD(LTC0_ESTA, LTC0_ESTA_ERRID1_MASK));
            return false;
        }
    }

    BME_BITFIELD(LTC0_STA, LTC0_STA_DI) = LTC0_STA_DI;

    return true;
}

/** Loads LTC register or its quadrant from value stored in RAM.
 * Will load register using data stored in RAM. If destination quadrant is other than
 * zero, then the size of value loaded may not be larger than 64 bytes. Otherwise it may 
 * be 256 bytes. Register E doesn't support quadrants so an attempt to write into non-zero 
 * quadrant of E register will fail.
 * @note If source address passed is NULL, then the load is skipped without returning an 
 *       error.
 * @param destination LTC register to store data into. If source is NULL then load is skipped.
 * @param source address of RAM location containing value to be loaded into register 
 * @returns true if load has been performed or skipped, false if arguments are invalid.
 */
__privileged bool ltc_load(pkha_reg_t destination, const pkha_number_t * source)
{
    uint32_t dst_reg = ((uint32_t) destination) >> 3;
    uint32_t dst_segment = ((uint32_t) destination) & 3;

    if (source == NULL)
    {
//        debug("Skipping load\n");
        return true;
    }

    if (dst_segment > 0)
    {
        if (dst_reg == _REG_E)
        {
            debug("Refusing to load into non-zero quadrant of E!\n");
            return false;
        }

        if (source->length > 64)
        {
            debug("Source length too long!\n");
            return false;
        }
    } else {
        if (source->length > 256)
        {
            debug("Source length too long!\n");
            return false;
        }
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
            debug("Invalid register specified!\n");
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

/** Stores value from LTC register or its quadrant into RAM.
 * Will store content of register into RAM. Register E is write only, so any attempt
 * to read from it will fail.
 * @param destination address of RAM location where the value has to be stored
 * @param source LTC register to read data from
 * @returns true if load has been performed, false if arguments are invalid.
 */
__privileged bool ltc_store(pkha_number_t * destination, pkha_reg_t source)
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

/** Compare content of LTC register with value in RAM.
 * Will compare number stored in RAM with number in LTC register. This operation 
 * will only compare valid digits of numbers. Register E is write-only and cannot
 * be compared. An attempt to compare it will fail.
 * @param source LTC register to compare
 * @param destination address of RAM region containing number to compare
 * @returns true if numbers are the same, false if they are of different length or 
 * have different value.
 */
__privileged bool ltc_compare(pkha_reg_t source, const pkha_number_t * destination)
{
    uint32_t src_reg = ((uint32_t) source) >> 3;
    uint32_t src_segment = ((uint32_t) source) & 3;
    uint32_t tmp_length;

    if (src_reg == _REG_E)
    {
        return false;
    }

    switch(src_reg)
    {
        case _REG_A:
            tmp_length = LTC0_PKASZ;
            break;
        case _REG_B:
            tmp_length = LTC0_PKBSZ;
            break;
        case _REG_N:
            tmp_length = LTC0_PKNSZ;
            break;
        default:
            return false;
    }

    if (tmp_length != destination->length)
    {
        return false;
    }

    uint32_t length32 = tmp_length / 4;
    if (tmp_length % 4 != 0)
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
        if (tmp_data != ((uint32_t *) destination->number)[q])
        {
            return false;
        }
    }

    return true;
}

__privileged ltc_pkha_result_t ltc_pkha_sign(
                    const pkha_curve_t * curve, /* curve parameters Cx,Cy,a,b,p */
                    const pkha_sign_input_t * input, /* private key, random value, message hash */
                    pkha_signature_t * output /* signature (r, s) */
                   )
{
    pkha_number_t tmp_h; /* a.k.a k^-1 - modular inverse of k */

    /* A0 <- A0 mod N */
    /* u = Nonce mod r */
    ltc_load(A0, &input->random_k);
    ltc_load(N0, &curve->n);
    if (!_ltc_mod_amodn(A0))
    {
        return LTC_Error;
    }

    /* h = 1/u mod r */
    ltc_mov(N2, A0, false);
    if (!_ltc_mod_inv(B0))
    {
        return LTC_Error;
    }


    /* V = u * G  (public key for u) */
    ltc_store(&tmp_h, B0);
    ltc_mov(B0, N2, false);

    ltc_load(A3, &(curve->a));
    ltc_load(A0, &(curve->Gx));
    ltc_load(A1, &(curve->Gy));

    ltc_mov(E, B0, false);

    ltc_load(B0, &(curve->b));
    ltc_load(N0, &(curve->p));

    if (!_ltc_ecc_mod_mul(B0))
    {
        return LTC_Error;
    }

    ltc_mov(A0, B1, false);
    ltc_load(N0, &curve->n);
    if (!_ltc_mod_amodn(B0))
    {
        return LTC_Error;
    }

    if (ltc_result_zero())
    {
        /* Result is point at infinity.
         * This is not really a bug or problem, just the random number
         * chosen was extremely unlucky. Restart this operation using
         * different value for random_k.
         */
        return LTC_BadRandomValue;
    }

    /* (s * c) mod r */
    /* B0 <- A0 * B0 mod R */
    ltc_store(&output->c, B0);
    tmp_ltc_dump_register(B0, "r");
    ltc_load(A0, &input->pkey);
    if (!_ltc_mod_mul(B0))
    {
        return LTC_Error;
    }


    /* B0 <- A0 + B0 mod R */
    /* (f + (s * c)) mod r */
    ltc_load(A0, &input->hash);
    if (!_ltc_mod_amodn(A0))
    {
        return LTC_Error;
    }

    if (!_ltc_mod_add(B0))
    {
        return LTC_Error;
    }

    /* d = (h * (f + s*c)) mod r */
    /* B0 <- A0 * B0 mod R */
    ltc_load(A0, &tmp_h);
    if (!_ltc_mod_mul(B0))
    {
        return LTC_Error;
    }

    if (ltc_result_zero())
    {
        /* Result is zero.
         * This is not really a bug or problem, just the random number
         * chosen was extremely unlucky. Restart this operation using
         * different value for random_k.
         */
        return LTC_BadRandomValue;
    }
    
    tmp_ltc_dump_register(B0, "s");
    ltc_store(&output->d, B0);

    return LTC_OK;
}

__privileged ltc_pkha_result_t ltc_pkha_verify(
                                            const pkha_curve_t * curve,
                                            const pkha_verify_input_t * input,
                                            const pkha_signature_t * signature
                                        )
{
    pkha_number_t tmp_buf1; /* u2, then t1_x */
    pkha_number_t tmp_buf2; /* t2_x */

    if (!ltc_mod_amodn(B0, &(signature->c), &(curve->n)))
    {
        return LTC_Error;
    }

    /* If A mod N differs from the original value, then c > N => fail*/
    if (ltc_result_zero() || !ltc_compare(B0, &(signature->c)))
    {
        return LTC_SignatureInvalid;
    }

    /* We pass modulo as NULL because we reuse the value 
     * loaded above */
    if (!ltc_mod_amodn(B0, &(signature->d), NULL))
    {
        return LTC_Error;
    }

    /* If A mod N differs from the original value, then c > N => fail*/
    if (ltc_result_zero() || !ltc_compare(B0, &(signature->d)))
    {
        return LTC_SignatureInvalid;
    }

    /* Here we use the raw access as all the operands are already
     * in place. Register A0 contains signature->d value left there by 
     * previous call to ltc_mod_amodn(). */
    _ltc_mod_inv(B0);

    /* Save inverse of signature->d for later use. Aliased as c in following code. */
    ltc_mov(N3, B0, false);

    /* u1 = (hash * c) mod n */
    /* B0 already contains value of c after call to _ltc_mod_inv() and N0 
     * still contains the modulus. */
    ltc_mod_mul(A0, &(input->hash), NULL, NULL);

    /* Save value u1 into N2 register for later use */
    ltc_mov(N2, A0, false);

    /* Reload value of c computed above from N3 register */
    ltc_mov(B0, N3, false);

    /* u2 = (r * c) mod n */
    /* B0 already contains value of c and N0 still contains the modulus */
    ltc_mod_mul(A0, &(signature->c), NULL, NULL);

    /* Save value of u2 into temporary buffer */
    ltc_store(&tmp_buf1, A0);

    /* You cannot move directly from non-zero segment into E. 
     * Restore temporary value into register E */
    ltc_mov(B0, N2, false);
    ltc_mov(E, B0, false);

    /* We pass scalar as NULL because we loaded register 
     * E above manually */
    ltc_ecc_mod_mul(B0, NULL, &(curve->Gx), &(curve->Gy),
                    &(curve->a), &(curve->b), &(curve->p));

    /* Pre-load value from tmp_buf1 into register E 
     * and then save temporaries into tmp_buf1 and tmp_buf2. */
    ltc_load(E, &tmp_buf1);

    /* Save result for later use */
    ltc_store(&tmp_buf1, B1);
    ltc_store(&tmp_buf2, B2);

    /* We pass scalar as NULL because we loaded 
     * register E from tmp_buf1 above manually */
    ltc_ecc_mod_mul(B0, NULL, &(input->Kx), &(input->Ky), 
                    &(curve->a), &(curve->b), &(curve->p));

    /* We pass p2.x, p2.y, curve.a, curve.b and curve.p as NULL 
     * because p2 coordinates were just calculated by above call 
     * to ltc_ecc_mod_mul and are in [B1, B2] and rest will be 
     * reused from previous call. */
    ltc_ecc_mod_add(A0, &tmp_buf1, &tmp_buf2, 
                    NULL, NULL, NULL, NULL, NULL);
    
    /* We pass A as NULL because we want to use the result of 
     * previous call to ltc_ecc_mod_add. */
    ltc_mod_amodn(A0, NULL, &(curve->n));

    if (ltc_compare(A0, &(signature->c)))
    {
        debug("Check Passed\n");
        return LTC_SignatureValid;
    }

    debug("Check Failed\n");
    return LTC_SignatureInvalid;

}

