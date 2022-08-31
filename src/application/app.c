/**
 ******************************************************************************
 * @file    app.c
 * @author  CZ.NIC, z.s.p.o.
 * @date    25-September-2015
 * @brief   Init and cyclic high level operations.
 ******************************************************************************
 ******************************************************************************
 **/
/* Includes ------------------------------------------------------------------*/
#include "power_control.h"
#include "debounce.h"
#include "led_driver.h"
#include "slave_i2c_device.h"
#include "wan_lan_pci_msata.h"
#include "debug.h"
#include "eeprom.h"
#include "cpu.h"
#include "flash.h"
#include "memory_layout.h"
#include "time.h"
#include "watchdog.h"

#define MAX_ERROR_COUNT		5
#define SET_INTERRUPT_TO_CPU	gpio_write(INT_MCU_PIN, 0)
#define RESET_INTERRUPT_TO_CPU	gpio_write(INT_MCU_PIN, 1)

typedef enum {
	OK			= 0,
	GO_TO_LIGHT_RESET	= 1,
	GO_TO_HARD_RESET	= 2,
	GO_TO_BOOTLOADER	= 3,
} ret_value_t;

typedef enum {
	POWER_ON,
	LIGHT_RESET,
	HARD_RESET,
	ERROR_STATE,
	INPUT_MANAGER,
	I2C_MANAGER,
	LED_MANAGER,
	BOOTLOADER
} states_t;

/*******************************************************************************
  * @function   app_mcu_init
  * @brief      Initialization of MCU and its ports and peripherals.
  * @param      None.
  * @retval     None.
  *****************************************************************************/
static void app_mcu_init(void)
{
	debug_init();

	flash_init(); /* Unlock the Flash Program Erase controller */

	time_config();
	/* init ports and peripheral */
	power_control_io_config();
	wan_lan_pci_msata_config();
	power_control_usb_timeout_config();
	led_driver_config();
	slave_i2c_config();

	/* new features for Omnia32 */
	if (OMNIA_BOARD_REVISION >= 32)
		periph_control_io_config();

	debug("\nInit completed.\n");
}

/*******************************************************************************
  * @function   app_get_status_word
  * @brief      Set status word after reset.
  * @param      None.
  * @retval     system_status_word.
  *****************************************************************************/
static uint16_t app_get_status_word(void)
{
	uint16_t status_word = STS_MCU_TYPE;

	/* GET_FEATURES command is supported */
	status_word |= STS_FEATURES_SUPPORTED;

#if USER_REGULATOR_ENABLED
	if (gpio_read_output(ENABLE_4V5_PIN))
		status_word |= STS_ENABLE_4V5;
#else
	status_word |= STS_USER_REGULATOR_NOT_SUPPORTED;
#endif

	if (msata_pci_card_detection())
		status_word |= STS_CARD_DET;

	if (msata_pci_type_card_detection())
		status_word |= STS_MSATA_IND;

	if (power_control_get_usb_overcurrent(USB3_PORT0))
		status_word |= STS_USB30_OVC;

	if (power_control_get_usb_overcurrent(USB3_PORT1))
		status_word |= STS_USB31_OVC;

	if (power_control_get_usb_poweron(USB3_PORT0))
		status_word |= STS_USB30_PWRON;

	if (power_control_get_usb_poweron(USB3_PORT1))
		status_word |= STS_USB31_PWRON;

	return status_word;
}

/*******************************************************************************
  * @function   app_get_ext_status_dword
  * @brief      Get value for extended status word after reset.
  * @param      None.
  * @retval     features.
  *****************************************************************************/
static uint32_t app_get_ext_status_dword(void)
{
	uint32_t ext_status_dword = 0;

	if (OMNIA_BOARD_REVISION >= 32) {
		if (gpio_read(SFP_nDET_PIN))
			ext_status_dword |= EXT_STS_SFP_nDET;
	}

	return ext_status_dword;
}

/*******************************************************************************
  * @function   power_on
  * @brief      Start the board / enable dc-dc regulators.
  * @param      None.
  * @retval     0 on success, -n if enableing n-th regulator failed.
  *****************************************************************************/
static int power_on(void)
{
	power_control_set_startup_condition();
	power_control_disable_regulators();

	msleep(100);

	return power_control_enable_regulators();
}

/*******************************************************************************
  * @function   light_reset
  * @brief      Perform light reset of the board.
  * @param      None.
  * @retval     value: next_state.
  *****************************************************************************/
static ret_value_t light_reset(void)
{
	ret_value_t value = OK;
	uint16_t ext_control = 0;

	led_driver_reset_effect(DISABLE);

	power_control_first_startup();

	/* set active reset of peripherals after CPU reset on v32+ boards */
	if (OMNIA_BOARD_REVISION >= 32)
		ext_control = periph_control_rst_init();

	watchdog_set_timeout(WATCHDOG_DEFAULT_TIMEOUT);
	watchdog_enable(true);

	led_driver_reset_effect(ENABLE);

	debounce_config(); /* start evaluation of inputs */
	i2c_status.status_word = app_get_status_word();
	i2c_status.ext_status_dword = app_get_ext_status_dword();
	i2c_status.ext_control_word = ext_control | EXT_CTL_PHY_SFP_AUTO;

	return value;
}

/*******************************************************************************
  * @function   input_manager
  * @brief      Evaluate input signals and their reaction.
  * @param      None.
  * @retval     value: next_state.
  *****************************************************************************/
static ret_value_t input_manager(void)
{
	ret_value_t value = OK;
	struct input_sig *input_state = &debounce_input_signal;
	struct button_def *button = &button_front;

	debounce_check_inputs();

	/* manual reset button */
	if (input_state->man_res) {
		value = GO_TO_LIGHT_RESET;
		input_state->man_res = false;
	}

	/* sw reset */
	if (input_state->sysres_out) {
		value = GO_TO_LIGHT_RESET;
		input_state->sysres_out = false;
	}

	/* PG signals from all DC/DC regulator (except of 4.5V user regulator) */
	if (input_state->pg) {
		debug("PG all regulators\n");
		value = GO_TO_HARD_RESET;
		input_state->pg = false;
	}

#if USER_REGULATOR_ENABLED
	/* PG signal from 4.5V user controlled regulator */
	if (input_state->pg_4v5) {
		debug("PG from 4V5\n");
		value = GO_TO_HARD_RESET;
		input_state->pg_4v5 = false;
	}
#endif

	/* USB30 overcurrent */
	if (input_state->usb30_ovc) {
		i2c_status.status_word |= STS_USB30_OVC;
		input_state->usb30_ovc = false;
		power_control_usb(USB3_PORT0, false); /* USB power off */

		/* update status word */
		if (!power_control_get_usb_poweron(USB3_PORT0))
			i2c_status.status_word &= ~STS_USB30_PWRON;

		/* USB timeout set to 1 sec */
		power_control_usb_timeout_enable();
	}

	/* USB31 overcurrent */
	if (input_state->usb31_ovc) {
		i2c_status.status_word |= STS_USB31_OVC;
		input_state->usb31_ovc = false;

		power_control_usb(USB3_PORT1, false); /* USB power off */

		/* update status word */
		if (!power_control_get_usb_poweron(USB3_PORT1))
			i2c_status.status_word &= ~STS_USB31_PWRON;

		/* USB timeout set to 1 sec */
		power_control_usb_timeout_enable();
	}

	/* front button */
	if (input_state->button_sts) {
		if (button->button_mode == BUTTON_DEFAULT)
			led_driver_step_brightness();
		else
			/* user button mode */
			button_counter_increase();

		input_state->button_sts = false;
	}

	/* in case of user button mode:
	 * store information in status_word - how many times a button was pressed  */
	if (button->button_mode != BUTTON_DEFAULT) {
		if (button->button_pressed_counter) {
			i2c_status.status_word &= ~STS_BUTTON_COUNTER_MASK;
			i2c_status.status_word |= (button->button_pressed_counter << 13) & STS_BUTTON_COUNTER_MASK;
			i2c_status.status_word |= STS_BUTTON_PRESSED;
		} else {
			i2c_status.status_word &= ~(STS_BUTTON_PRESSED | STS_BUTTON_COUNTER_MASK);
		}
	}

	/* these flags are automatically cleared in debounce function */
	if (input_state->card_det)
		i2c_status.status_word |= STS_CARD_DET;
	else
		i2c_status.status_word &= ~STS_CARD_DET;

	if (input_state->msata_ind)
		i2c_status.status_word |= STS_MSATA_IND;
	else
		i2c_status.status_word &= ~STS_MSATA_IND;


	if (OMNIA_BOARD_REVISION >= 32) {
		if (gpio_read(SFP_nDET_PIN))
			i2c_status.ext_status_dword |= EXT_STS_SFP_nDET;
		else
			i2c_status.ext_status_dword &= ~(EXT_STS_SFP_nDET);

		disable_irq();
		if (i2c_status.ext_control_word & EXT_CTL_PHY_SFP_AUTO)
			gpio_write(PHY_SFP_PIN,
				   !!(i2c_status.ext_status_dword & EXT_STS_SFP_nDET));
		enable_irq();
	}

	return value;
}

/*******************************************************************************
  * @function   i2c_manager
  * @brief      Handle I2C communication.
  * @param      None.
  * @retval     value: next_state.
  *****************************************************************************/
static ret_value_t i2c_manager(void)
{
	static uint16_t last_status_word;
	ret_value_t value = OK;

	if (i2c_status.status_word != last_status_word)
		SET_INTERRUPT_TO_CPU;
	else
		RESET_INTERRUPT_TO_CPU;

	last_status_word = i2c_status.status_word;

	switch (i2c_status.state) {
	case SLAVE_I2C_LIGHT_RST:
		value = GO_TO_LIGHT_RESET;
		break;

	case SLAVE_I2C_HARD_RST:
		value = GO_TO_HARD_RESET;
		break;

	case SLAVE_I2C_GO_TO_BOOTLOADER:
		value = GO_TO_BOOTLOADER;
		break;

	default:
		value = OK;
		break;
	}

	i2c_status.state = SLAVE_I2C_OK;

	return value;
}

/*******************************************************************************
  * @function   led_manager
  * @brief      System LED activity (WAN, LAN, WiFi...).
  * @param      None.
  * @retval     next_state.
  *****************************************************************************/
static ret_value_t led_manager(void)
{
	wan_led_activity();
	lan_led_activity();
	pci_led_activity();
	msata_pci_activity();
	led_states_commit();

	return OK;
}

/*******************************************************************************
  * @function   error_manager
  * @brief      Handle error occuring in startup.
  * @param      err_led: LED index indicating the error
  * @retval     None.
  *****************************************************************************/
static void error_manager(unsigned led)
{
	led_set_user_mode(LED_COUNT, false);
	led_set_state(LED_COUNT, false);
	led_set_color24(LED_COUNT, RED_COLOR);

	msleep(300);

	led_set_state(led, true);

	msleep(300);
}

/*******************************************************************************
  * @function   app_mcu_cyclic
  * @brief      Main cyclic function.
  * @param      None.
  * @retval     None.
  *****************************************************************************/
static void app_mcu_cyclic(void)
{
	static states_t next_state = POWER_ON;
	static ret_value_t val = OK;
	static int err;
	static uint8_t error_counter;

	switch (next_state) {
	case POWER_ON:
		err = power_on();

		if (!err)
			next_state = LIGHT_RESET;
		else
			next_state = ERROR_STATE;
		break;

	case LIGHT_RESET:
		val = light_reset();

		next_state = INPUT_MANAGER;
		break;

	case HARD_RESET:
		NVIC_SystemReset();
		break;

	case ERROR_STATE:
		error_manager(-err - 1);
		error_counter++;

		if (error_counter >= MAX_ERROR_COUNT) {
			next_state = HARD_RESET;
			error_counter = 0;
		} else {
			next_state = ERROR_STATE;
		}
		break;

	case INPUT_MANAGER:
		val = input_manager();

		switch (val) {
		case GO_TO_LIGHT_RESET:
			next_state = LIGHT_RESET;
			break;

		case GO_TO_HARD_RESET:
			next_state = HARD_RESET;
			break;

		default:
			next_state = I2C_MANAGER;
			break;
		}
		break;

	case I2C_MANAGER:
		val = i2c_manager();

		switch (val) {
		case GO_TO_LIGHT_RESET:
			next_state = LIGHT_RESET;
			break;

		case GO_TO_HARD_RESET:
			next_state = HARD_RESET;
			break;

		case GO_TO_BOOTLOADER:
			next_state = BOOTLOADER;
			break;

		default:
			next_state = LED_MANAGER;
			break;
		}
		break;

	case LED_MANAGER:
		if (effect_reset_finished)
			led_manager();

		next_state = INPUT_MANAGER;
		break;

	case BOOTLOADER:
		reset_to_address(BOOTLOADER_BEGIN);
		break;
	}
}

void main(void)
{
	enable_irq();

	app_mcu_init();

	while (1)
		app_mcu_cyclic();
}
