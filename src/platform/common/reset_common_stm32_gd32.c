#if defined(STM32F030X8) || defined(GD32F1x0)

#include "debug.h"
#include "firmware_flash.h"
#include "i2c_iface.h"
#include "reset_common_stm32_gd32.h"
#include "wear_leveled_storage.h"

static bool bootloader_has_feature(uint16_t feature)
{
	const features_t *ptr = (const void *)BOOTLOADER_FEATURES;

	if (ptr->magic != FEATURES_MAGIC)
		return false;

	if (ptr->csum != crc32_plat(0, ptr, 8))
		return false;

	return ptr->features & feature;
}

void old_type_bootloader_request_if_needed(void)
{
	/*
	 * Check whether the bootloader supports the new messaging mechanism
	 * (via CRC engine free data register on STM32/GD32). If it does, we do
	 * not need to send the "stay in bootloader" request via the old
	 * mechanism.
	 */
	if (bootloader_has_feature(FEAT_NEW_MESSAGE_API)) {
		debug("old type bootloader request not needed\n");
		return;
	}

	debug("setting old type bootloader request\n");
	wls_set_var(WLS_VAR_RESET_REASON, STAY_IN_BOOTLOADER_REQ);
}

#endif /* defined(STM32F030X8) || defined(GD32F1x0) */
