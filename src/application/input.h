#ifndef __INPUT_H
#define __INPUT_H

#include "compiler.h"

/* flags of input signals */
typedef struct {
	unsigned man_res	: 1;
	unsigned sysres_out	: 1;
	unsigned dbg_res	: 1;
	unsigned m_res		: 1;
	unsigned pg		: 1;
	unsigned pg_4v5		: 1;
	unsigned usb30_ovc	: 1;
	unsigned usb31_ovc	: 1;
	unsigned rtc_alarm	: 1;
	unsigned card_det	: 1;
	unsigned msata_ind	: 1;
} input_state_t;

typedef struct {
	bool user_mode;
	uint8_t pressed_counter;
	bool state;
} button_t;

extern input_state_t input_state;
extern button_t button;

/*******************************************************************************
  * @function   button_debounce_handler
  * @brief      Button debounce function. Called from SysTick handler every 5 ms.
  * @param      None.
  * @retval     None.
  *****************************************************************************/
void button_debounce_handler(void);

/*******************************************************************************
  * @function   input_signals_handler
  * @brief      Check input signal.
  * @param      None.
  * @retval     None.
  *****************************************************************************/
void input_signals_handler(void);

/*******************************************************************************
  * @function   button_counter_decrease
  * @brief      Decrease button counter by the current value in i2c status structure.
  * @param      value: decrease the button counter by this parameter
  * @retval     None.
  *****************************************************************************/
void button_counter_decrease(uint8_t value);

#endif /* __INPUT_H */