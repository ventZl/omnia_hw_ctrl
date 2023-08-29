#if !BOOTLOADER_BUILD

/*
 * Non-volatile wear-leveled variable storage
 * ==========================================
 *
 * In order to do an application firmware update, it is required to stop
 * executing the current application firmware, and switch to bootloader
 * firmware. By default, bootloader firmware immediately starts executing
 * application firmware again. In order to stop this and keep executing
 * bootloader firmware after the switch, there needs to be a mechanism to tell
 * the bootloader to stay there.
 *
 * On STM32 and GD32 platforms, this is currently done by using the CRC engine
 * free data register (see the set_reset_reason() function in reset.h). But this
 * is the new mechanism introduced in commit eb5c9a8dd9ec ("Add new API for
 * sending message between bootloader and application").
 *
 * Older versions of bootloader firmware only support the old method, wherein
 * the last two pages of the flash are used for wear-leveled variable storage.
 * In the old versions of the code this was called EEPROM simulation and we
 * dropped it in commit 89c8c97c61b9 ("Get rid of EEPROM emulation, it isn't
 * needed anymore").
 *
 * Flashing a version of the application firmware that does not support the old
 * message passing mechanism onto a board with old bootloader firmware would
 * result in the inability to flash application firmware again (since we would
 * be unable to tell the bootloader to not to immediately execute application).
 *
 * Therefore, in order to be able to upgrade the application firmware to the
 * newest version without requiring the users to also upgrade the bootloader
 * firmware (which may result in a bricked board if interrupted), we
 * re-introduce this wear-leveled variable storage support again.
 */

#include "debug.h"
#include "flash_plat.h"
#include "memory_layout.h"
#include "wear_leveled_storage.h"

enum wls_status_e {
	WLS_ERASED = 0xffff,
	WLS_VALID  = 0x0000,
	WLS_RECV   = 0xeeee,
};

struct wls_var_s {
	union {
		struct {
			uint16_t value;
			uint16_t id;
		};
		uint32_t raw;
	};
};

typedef volatile const struct wls_var_s wear_leveled_var_t;

typedef volatile const struct {
	uint16_t status;
	uint16_t reserved;
	wear_leveled_var_t vars[(FLASH_PAGE_SIZE - 4) /
				sizeof(wear_leveled_var_t)];
} wear_leveled_storage_t;

static wear_leveled_storage_t wear_leveled_storage[2] __section(".wls");

static wear_leveled_storage_t *wls_next(wear_leveled_storage_t *wls)
{
	if (++wls == &wear_leveled_storage[ARRAY_SIZE(wear_leveled_storage)])
		return &wear_leveled_storage[0];
	else
		return wls;
}

static wear_leveled_var_t *wls_find_free_var(wear_leveled_storage_t *wls)
{
	for_each(var, wls->vars)
		if (var->raw == 0xffffffffU)
			return var;

	return NULL;
}

static bool wls_ensure_erased(wear_leveled_storage_t *wls)
{
	bool res;

	if (wls->status == WLS_ERASED)
		return true;

	res = flash_sync_erase((uint32_t)wls, FLASH_PAGE_SIZE);

	if (!res)
		debug("failed erasing wls\n");

	return res;
}

static bool wls_set_valid(wear_leveled_storage_t *wls)
{
	uint16_t status = WLS_VALID;

	bool res = flash_sync_write((uint32_t)&wls->status, (void *)&status,
				    sizeof(status));

	if (!res)
		debug("failed setting wls valid\n");

	return res;
}

static bool wls_program_var(wear_leveled_var_t *var, wls_var_id_t id,
			    uint16_t value)
{
	struct wls_var_s buf;
	bool res;

	buf.id = id;
	buf.value = value;

	res = flash_sync_write((uint32_t)var, (void *)&buf, sizeof(buf));

	if (!res)
		debug("failed setting wls var\n");

	return res;
}

static wear_leveled_storage_t *wls_get_valid(void)
{
	wear_leveled_storage_t *wls;

	for_each(wls, wear_leveled_storage)
		if (wls->status == WLS_VALID)
			return wls;

	/* if there is no valid storage, create one */
	wls = &wear_leveled_storage[0];
	if (!wls_ensure_erased(wls) || !wls_set_valid(wls))
		return NULL;

	return wls;
}

static wear_leveled_storage_t *wls_transfer(wear_leveled_storage_t *wls)
{
	wear_leveled_storage_t *next = wls_next(wls);

	if (!wls_ensure_erased(next))
		return NULL;

	/*
	 * If there were multiple possible variables, we would need to transfer
	 * them to the new page. But currently we support only the
	 * WLS_VAR_RESET_REASON variable, so we can simply erase.
	 */

	if (!wls_ensure_erased(wls))
		return NULL;

	if (!wls_set_valid(next))
		return NULL;

	return next;
}

bool wls_set_var(wls_var_id_t id, uint16_t value)
{
	wear_leveled_storage_t *wls;
	wear_leveled_var_t *var;

	wls = wls_get_valid();
	if (!wls)
		return false;

	var = wls_find_free_var(wls);
	if (!var) {
		wls = wls_transfer(wls);
		if (!wls)
			return false;

		var = wls_find_free_var(wls);
		if (!var)
			return false;
	}

	return wls_program_var(var, id, value);
}

#endif /* !BOOTLOADER_BUILD */
