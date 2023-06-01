#ifndef RESET_COMMON_H
#define RESET_COMMON_H

#include "cpu.h"

#define RESET_REASON_MSG_MAGIC	0xdeadbeef

typedef enum {
	NORMAL_BOOT		= 0x00,
	STAY_IN_BOOTLOADER_REQ	= 0xaa,
	APPLICATION_FAULT	= 0xee,
} reset_reason_t;

typedef struct {
	uint32_t fault;
} reset_reason_info_t;

static __force_inline __noreturn void reset_to_address(uint32_t isr_vec_addr)
{
	__noreturn void (*new_reset_handler)(void);
	uint32_t sp;

	disable_irq();

	/* get stack pointer from ISR vector */
	sp = *(volatile uint32_t *)isr_vec_addr;

	new_reset_handler = (void *)*(volatile uint32_t *)(isr_vec_addr + 4);

	/* set stack pointer */
	set_msp(sp);

	/* instruction synchronization barrier to flush pipeline */
	isb();

	/* branch instead of call so that nothing is pushed to stack */
	asm volatile("bx %0\n\t" : : "r" (new_reset_handler));
	unreachable();
}

#endif /* RESET_COMMON_H */
