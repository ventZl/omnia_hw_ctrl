#ifndef RESET_H
#define RESET_H

#include "reset_common.h"
#include "memory_layout.h"

static inline reset_reason_t get_reset_reason(reset_reason_info_t *info)
{
	if (RFSYS(0) != RESET_REASON_MSG_MAGIC)
		return NORMAL_BOOT;

	RFSYS(0) = 0;

	switch (RFSYS(1)) {
	case STAY_IN_BOOTLOADER_REQ:
		return STAY_IN_BOOTLOADER_REQ;

	case APPLICATION_FAULT:
		info->fault = RFSYS(2);
		return APPLICATION_FAULT;

	default:
		return NORMAL_BOOT;
	}
}

static inline void set_reset_reason(reset_reason_t reason, uint32_t fault)
{
	compiletime_assert(reason != NORMAL_BOOT, "Invalid reset reason");

	RFSYS(0) = RESET_REASON_MSG_MAGIC;
	RFSYS(1) = reason;
	RFSYS(2) = fault;
}

static __noreturn inline void soft_reset_to_other_program(void)
{
	if (!BOOTLOADER_BUILD)
		set_reset_reason(STAY_IN_BOOTLOADER_REQ, 0);

	reset_to_address(BOOTLOADER_BUILD ? APPLICATION_BEGIN
					  : BOOTLOADER_BEGIN);
}

#endif /* RESET_H */
