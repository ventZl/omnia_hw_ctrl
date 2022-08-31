/**
 ******************************************************************************
 * @file    debounce.c
 * @author  CZ.NIC, z.s.p.o.
 * @date    21-July-2015
 * @brief   Debounce switches and inputs from PG signals
 ******************************************************************************
 ******************************************************************************
 **/
#include "debounce.h"
#include "power_control.h"
#include "time.h"
#include "led_driver.h"
#include "wan_lan_pci_msata.h"
#include "debug.h"
#include "i2c_iface.h"
#include "timer.h"

enum input_mask {
	MAN_RES_MASK	= 0x0001,
	SYSRES_OUT_MASK	= 0x0002,
	DBG_RES_MASK	= 0x0004,
	MRES_MASK	= 0x0008,
	PG_5V_MASK	= 0x0010,
	PG_3V3_MASK	= 0x0020,
	PG_1V35_MASK	= 0x0040,
	PG_4V5_MASK	= 0x0080,
	PG_1V8_MASK	= 0x0100,
	PG_1V5_MASK	= 0x0200,
	PG_1V2_MASK	= 0x0400,
	PG_VTT_MASK	= 0x0800,
	USB30_OVC_MASK	= 0x1000,
	USB31_OVC_MASK	= 0x2000,
	RTC_ALARM_MASK	= 0x4000,
	BUTTON_MASK	= 0x8000,
};

struct input_sig debounce_input_signal;
struct button_def button_front;

/*******************************************************************************
  * @function   button_debounce_handler
  * @brief      Button debounce function. Called from SysTick handler every 5 ms.
  * @param      None.
  * @retval     None.
  *****************************************************************************/
void button_debounce_handler(void)
{
	static uint16_t idx;
	struct button_def *button = &button_front;

	/* port B, pins 0-14 debounced by general function debounce_check_inputs() */
	/* only button on PB15 is debounced here, but read the whole port */
	button->button_pin_state[idx] = ~gpio_read_port(PORT_B);
	idx++;

	if (idx >= MAX_BUTTON_DEBOUNCE_STATE)
		idx = 0;
}

/*******************************************************************************
  * @function   debounce_check_inputs
  * @brief      Check input signal.
  * @param      None.
  * @retval     None.
  *****************************************************************************/
void debounce_check_inputs(void)
{
	uint16_t port_changed, button_changed;
	static uint16_t last_button_debounce_state;
	struct input_sig *input_state = &debounce_input_signal;
	struct button_def *button = &button_front;

	/* PB0-14 ----------------------------------------------------------------
	 * No debounce is used now (we need a reaction immediately) */

	/* read the whole port */
	port_changed = ~gpio_read_port(PORT_B);

	/* PB15 ------------------------------------------------------------------
	 * button debounce */
	last_button_debounce_state = button->button_debounce_state;
	button->button_debounce_state = BUTTON_MASK;

	for (int i = 0; i < MAX_BUTTON_DEBOUNCE_STATE; i++)
		button->button_debounce_state = button->button_debounce_state &
						button->button_pin_state[i];

	button_changed = (button->button_debounce_state ^
			  last_button_debounce_state) &
			 button->button_debounce_state;

	input_state->card_det = msata_pci_card_detection();
	input_state->msata_ind = msata_pci_type_card_detection();

	/* results evaluation --------------------------------------------------- */
	if (port_changed & MAN_RES_MASK) {
		input_state->man_res = true;
		/* set CFG_CTRL pin to high state ASAP */
		gpio_write(CFG_CTRL_PIN, 1);
	}

	if (port_changed & SYSRES_OUT_MASK)
		input_state->sysres_out = true;

	if (OMNIA_BOARD_REVISION < 32) {
		if (port_changed & DBG_RES_MASK) {
			/* no reaction necessary */
		}

		/* reaction: follow MRES signal */
		gpio_write(RES_RAM_PIN, !(port_changed & MRES_MASK));
	}

	if ((port_changed & PG_5V_MASK) || (port_changed & PG_3V3_MASK) ||
	    (port_changed & PG_1V35_MASK) || (port_changed & PG_VTT_MASK) ||
	    (port_changed & PG_1V8_MASK) || (port_changed & PG_1V5_MASK) ||
	    (port_changed & PG_1V2_MASK))
		input_state->pg = true;

	/* PG signal from 4.5V user controlled regulator */
	if ((i2c_iface.status_word & STS_ENABLE_4V5) &&
	    (port_changed & PG_4V5_MASK))
		input_state->pg_4v5 = true;

	if (port_changed & USB30_OVC_MASK)
		input_state->usb30_ovc = true;

	if (port_changed & USB31_OVC_MASK)
		input_state->usb31_ovc = true;

	if (port_changed & RTC_ALARM_MASK) {
		/* no reaction necessary */
	}

	if (button_changed & BUTTON_MASK)
		input_state->button_sts = true;
}

/*******************************************************************************
  * @function   debounce_config
  * @brief      Debouncer configuration.
  * @param      None.
  * @retval     None.
  *****************************************************************************/
void debounce_config(void)
{
	struct button_def *button = &button_front;

	/* default = brightness settings */
	button->button_mode = BUTTON_DEFAULT;
}

/*******************************************************************************
  * @function   button_counter_decrease
  * @brief      Decrease button counter by the current value in i2c status structure.
  * @param      value: decrease the button counter by this parameter
  * @retval     None.
  *****************************************************************************/
void button_counter_decrease(uint8_t value)
{
	struct button_def *button = &button_front;

	button->button_pressed_counter -= value;

	/* limitation */
	if (button->button_pressed_counter < 0)
		button->button_pressed_counter = 0;
}

/*******************************************************************************
  * @function   button_counter_increase
  * @brief      Increase button counter.
  * @param      None.
  * @retval     None.
  *****************************************************************************/
void button_counter_increase(void)
{
	struct button_def *button = &button_front;

	button->button_pressed_counter++;

	/* limitation */
	if (button->button_pressed_counter > MAX_BUTTON_PRESSED_COUNTER)
		button->button_pressed_counter = MAX_BUTTON_PRESSED_COUNTER;
}
