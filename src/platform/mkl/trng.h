#pragma once

#include "cpu.h"
#include "svc.h"
#include "mkl81.h"
#include "clock.h"

static inline bool trng_ready();
static inline bool trng_error();

/** Initialize the TRNG peripheral.
 * This will enable clock to the TRNG peripheral,
 * reset all of its registers, switch into normal mode
 * and enable entropy generation.
 * Interrupt for TRNG is muxed at channel 1 of INTMUX.
 */
static inline __privileged void trng_init(void)
{
    clk_config(TRNG_Slot, 1);
	/* enable INTMUX and TRNG clock */
	BME_OR(SIM_SCGC6) = SIM_SCGC6_TRNG;

	/* Put TRNG into program mode and reset all the registers 
     * into default state. */
    BME_OR(TRNG0_MCTL) = TRNG0_MCTL_PRGM;
    BME_OR(TRNG0_MCTL) = TRNG0_MCTL_RST_DEF;

    /* If CPU is clocked too fast, then ring oscillator might 
     * run for too long and exceed the default FRQMAX limit.
     * This will lead to FRQ_ERR and TRNG will block.
     */
    BME_BITFIELD(TRNG0_MCTL, TRNG0_MCTL_OSC_DIV_MASK) = TRNG0_MCTL_OSC_DIV_8;

    /* Put TRNG back into normal mode, so entropy generation
     * can be fired later */
    BME_AND(TRNG0_MCTL) = ~TRNG0_MCTL_PRGM;

    /* Use only polling approach for now to test the code */
#ifdef TRNG_USE_INTERRUPTS
	/* reset INTMUX channel 1 and mux TRNG IRQ */
	INTMUX_CHn_CSR(1) = INTMUX_CHn_CSR_RST;
	INTMUX_CHn_IER(1) = BIT(TRNG0_IRQn);

	/* enable INTMUX channel 0 interrupt; LTC IRQ must preempt SVC */
    /* TODO: check for correct LTC IRQ priority */
	nvic_enable_irq_with_prio(INTMUX0_1_IRQn, 2);
#endif

    /* Enable entropy generation */
    BME_OR(TRNG0_MCTL) = TRNG0_MCTL_TRNG_ACC;
}

SYSCALL(trng_init)

/** Stop TRNG peripheral.
 * This function will wait for ring oscillator to 
 * stop and then will stop the peripheral.
 */
static inline void trng_stop()
{
    while (!(TRNG0_MCTL & TRNG0_MCTL_TSTOP_OK)) {};
    BME_AND(SIM_SCGC6) = ~SIM_SCGC6_TRNG;
}

/** Switches TRNG into programming mode.
 * In programming mode TRNG operation is disabled,
 * oscillator is stopped and TRNG is ready to be 
 * configured.
 */
static inline void trng_program()
{
    BME_BITFIELD(TRNG0_MCTL, TRNG0_MCTL_PRGM) = TRNG0_MCTL_PRGM;
}

/** Switched TRNG into run mode.
 * In run mode, it is possible to generate entropy.
 * In this mode, TRNG settings cannot be changed.
 */
static inline void trng_run()
{
    BME_BITFIELD(TRNG0_MCTL, TRNG0_MCTL_PRGM) = 0; 
    BME_BITFIELD(TRNG0_MCTL, TRNG0_MCTL_TRNG_ACC) = 1;
}

/** Read entropy from TRNG.
 * This will read 512 bits of entropy from TRNG after
 * TRNG states that entropy is valid. If entropy is not
 * valid, then this function will wait for available entropy.
 * Thus it is usable both in polling and interrupt-driven
 * modes.
 * After entropy has been read, next entropy generation 
 * cycle is fired automatically.
 * @param [out] dest target to store entropy data
 */
static inline bool trng_entropy(uint32_t dest[16])
{
    /* If any error is reported, bail out */
    if (trng_error())
        return false;

    while (!trng_ready()) {}

    for (unsigned q = 0; q < 16; ++q)
    {
        dest[q] = TRNG0_ENT(q);
    }

    /* reading ENT(15) will fire next entropy generation */
    return true;
}

SYSCALL(trng_entropy, uint32_t *)

/** Discard available entropy, generate another data.
 * This will discard any generated entropy and start another
 * round of entropy generation. If entropy is not valid, will
 * wait for valid entropy and then discard it.
 */
static inline bool trng_discard()
{
    /* If any error is reported, bail out */
    if (trng_error())
        return false;

    /* wait for entropy to be valid */
    while (BME_BITFIELD(TRNG0_MCTL, TRNG0_MCTL_ENT_VAL) == 0) {}

    /* reading ENT(15) will fire next entropy generation */
    (void)TRNG0_ENT(15);

    return true;
}

/** Get entropy availability status.
 * @returns true if 512 bits of entropy is avaiable, false otherwise
 */
static inline __privileged bool trng_ready()
{
    return ((TRNG0_MCTL & TRNG0_MCTL_ENT_VAL) != 0);
}

SYSCALL(trng_ready)

/** Get error status.
 * @return true if error occurred.
 */
static inline bool trng_error()
{
    return (BME_BITFIELD(TRNG0_MCTL, TRNG0_MCTL_ERR) != 0);
}
