#ifndef RESET_H
#define RESET_H

#include "memory_layout.h"
#include "crc32_plat.h"
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

static inline bool get_fault_info(uint32_t *fault)
{
	uint32_t *p = (uint32_t *)(RAM_END - RESET_REASON_MSG_LENGTH);

	if (p[0] != RESET_REASON_MSG_MAGIC)
		return false;

	if (p[3] != crc32_plat(0xffffffff, p, 12))
		return false;

	*fault = p[1];

	/* invalidate */
	p[0] = 0;

	return true;
}

static inline void set_fault_info(uint32_t fault)
{
	uint32_t *p = (uint32_t *)(RAM_END - RESET_REASON_MSG_LENGTH);

	crc32_enable();

	p[0] = RESET_REASON_MSG_MAGIC;
	p[1] = fault;
	p[2] = crc32_plat(0xffffffff, (void *)RAM_BEGIN, RAM_LENGTH - 0x200);
	dsb();
	p[3] = crc32_plat(0xffffffff, p, 12);

	nvic_system_reset();
}

static inline reset_reason_t get_reset_reason(reset_reason_info_t *info)
{
	if (get_fault_info(&info->fault)) {
		return APPLICATION_FAULT;
	} else if (CRC_FREE_DATA_REG == STAY_IN_BOOTLOADER_REQ) {
		CRC_FREE_DATA_REG = 0;
		return STAY_IN_BOOTLOADER_REQ;
	} else {
		return NORMAL_BOOT;
	}
}

void old_type_bootloader_request_if_needed(void);

static inline void set_reset_reason(reset_reason_t reason, uint32_t fault)
{
	compiletime_assert(reason != NORMAL_BOOT, "Invalid reset reason");

	switch (reason) {
	case APPLICATION_FAULT:
		return set_fault_info(fault);

	case STAY_IN_BOOTLOADER_REQ:
		CRC_FREE_DATA_REG = STAY_IN_BOOTLOADER_REQ;
		old_type_bootloader_request_if_needed();
		return;

	default:
		unreachable();
	}
}

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

static __noreturn inline void soft_reset_to_other_program(void)
{
	if (!BOOTLOADER_BUILD)
		set_reset_reason(STAY_IN_BOOTLOADER_REQ, 0);

	reset_to_address(BOOTLOADER_BUILD ? APPLICATION_BEGIN
					  : BOOTLOADER_BEGIN);
}

#endif /* RESET_H */
