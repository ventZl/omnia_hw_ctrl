#ifndef WEAR_LEVELED_STORAGE_H
#define WEAR_LEVELED_STORAGE_H

#include "compiler.h"

typedef enum {
	WLS_VAR_RESET_REASON = 0x8888,

	/*
	 * To support more than one variable ID, the wls_transfer() function
	 * needs to be rewritten to actually transfer variables from the old
	 * valid page.
	 */
} wls_var_id_t;

bool wls_set_var(wls_var_id_t id, uint16_t value);

#endif /* WEAR_LEVELED_STORAGE_H */
