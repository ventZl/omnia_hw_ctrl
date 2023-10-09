#include "power_control.h"
#include "input.h"
#include "led_driver.h"
#include "i2c_iface.h"
#include "debug.h"
#include "reset.h"
#include "cpu.h"
#include "flash.h"
#include "memory_layout.h"
#include "time.h"
#include "crc32.h"
#include "trng.h"
#include "ltc.h"

#define MAX_ERROR_COUNT		5

typedef enum {
	POWER_ON,
	LIGHT_RESET,
	HARD_RESET,
	ERROR_STATE,
	INPUT_MANAGER,
	I2C_MANAGER,
	BOOTLOADER
} state_t;

static i2c_iface_priv_t i2c_iface_priv;

static i2c_slave_t i2c_slave = {
	.cb = i2c_iface_event_cb,
	.priv = &i2c_iface_priv,
};

#if 0
// from python-ecdsa:src/ecdsa/ecdsa.py
const pkha_curve_t nist_p_256 = {
    .Gx = {
        { 0x96, 0xc2, 0x98, 0xd8, 0x45, 0x39, 0xa1, 0xf4,
          0xa0, 0x33, 0xeb, 0x2d, 0x81, 0x7d, 0x03, 0x77,
          0xf2, 0x40, 0xa4, 0x63, 0xe5, 0xe6, 0xbc, 0xf8,
          0x47, 0x42, 0x2c, 0xe1, 0xf2, 0xd1, 0x17, 0x6b },
        32
    },
    .Gy = {
        { 0xf5, 0x51, 0xbf, 0x37, 0x68, 0x40, 0xb6, 0xcb,
          0xce, 0x5e, 0x31, 0x6b, 0x57, 0x33, 0xce, 0x2b,
          0x16, 0x9e, 0x0f, 0x7c, 0x4a, 0xeb, 0xe7, 0x8e,
          0x9b, 0x7f, 0x1a, 0xfe, 0xe2, 0x42, 0xe3, 0x4f },
        32
    },
    .n = {
        {
          0x51, 0x25, 0x63, 0xfc, 0xc2, 0xca, 0xb9, 0xf3,
          0x84, 0x9e, 0x17, 0xa7, 0xad, 0xfa, 0xe6, 0xbc,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff },
        32
    },
    // Formally this is a value of -3, in fact the same as
    // -3 + .r above.
    .a = {
        { 0x4e, 0x25, 0x63, 0xfc, 0xc2, 0xca, 0xb9, 0xf3,
          0x84, 0x9e, 0x17, 0xa7, 0xad, 0xfa, 0xe6, 0xbc,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff },
        32
    },
    .b = {
        { 0x4b, 0x60, 0xd2, 0x27, 0x3e, 0x3c, 0xce, 0x3b,
          0xf6, 0xb0, 0x53, 0xcc, 0xb0, 0x06, 0x1d, 0x65,
          0xbc, 0x86, 0x98, 0x76, 0x55, 0xbd, 0xeb, 0xb3,
          0xe7, 0x93, 0x3a, 0xaa, 0xd8, 0x35, 0xc6, 0x5a },
        32
    }
};

const pkha_input_t input = {
    .random_k = {
        { 0x84, 0xf1, 0x2f, 0x5e, 0xf0, 0xda, 0x4c, 0xfe,
          0x9f, 0xa7, 0xa6, 0x0d, 0x8b, 0x75, 0x09, 0xf0,
          0x65, 0x9d, 0xbe, 0x3f, 0x36, 0x68, 0x03, 0xd1,
          0x06, 0x75, 0x2f, 0xc9, 0xb6, 0x8c, 0x29, 0x27 },
        32 
    },
    .pkey = {
        { 0xad, 0xde, 0xbe, 0xba, 0xad, 0xde, 0xbe, 0xba,
          0xad, 0xde, 0xbe, 0xba, 0xad, 0xde, 0xbe, 0xba,
          0xad, 0xde, 0xbe, 0xba, 0xad, 0xde, 0xbe, 0xba,
          0xad, 0xde, 0xbe, 0xba, 0xad, 0xde, 0xbe, 0xba },
        32

    },
    .hash = {
        { 0xe7, 0xb7, 0x6c, 0x95, 0x48, 0xcd, 0x4e, 0x58,
          0x33, 0x76, 0xad, 0xc5, 0x26, 0x5a, 0x97, 0x5b,
          0xce, 0x3f, 0x98, 0xaf, 0x6d, 0x1d, 0x3a, 0x67,
          0xc8, 0xe7, 0xff, 0x6a, 0x70, 0x60, 0x82, 0xd0 },
        32
    }
};

#else
// from python-ecdsa:src/ecdsa/ecdsa.py
const pkha_curve_t nist_p_192 = {
    .Gx = {
        { 0x12, 0x10, 0xff, 0x82, 0xfd, 0x0a, 0xff, 0xf4, 0x00, 0x88, 0xa1, 0x43, 0xeb, 0x20, 0xbf, 0x7c, 0xf6, 0x90, 0x30, 0xb0, 0x0e, 0xa8, 0x8d, 0x18 },
        24
    },
    .Gy = {
        { 0x11, 0x48, 0x79, 0x1e, 0xa1, 0x77, 0xf9, 0x73, 0xd5, 0xcd, 0x24, 0x6b, 0xed, 0x11, 0x10, 0x63, 0x78, 0xda, 0xc8, 0xff, 0x95, 0x2b, 0x19, 0x07 },
        24
    },
    .n = {
        { 0x31, 0x28, 0xd2, 0xb4, 0xb1, 0xc9, 0x6b, 0x14, 0x36, 0xf8, 0xde, 0x99, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
        24
    },
    // Formally this is a value of -3, in fact the same as
    // -3 + .r above.
    .a = {
        { 0x2e, 0x28, 0xd2, 0xb4, 0xb1, 0xc9, 0x6b, 0x14, 0x36, 0xf8, 0xde, 0x99, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
        24
    },
    .b = {
        { 0xb1, 0xb9, 0x46, 0xc1, 0xec, 0xde, 0xb8, 0xfe, 0x49, 0x30, 0x24, 0x72, 0xab, 0xe9, 0xa7, 0x0f, 0xe7, 0x80, 0x9c, 0xe5, 0x19, 0x05, 0x21, 0x64 },
        24
    }
};

// from python-ecdsa:src/ecdsa/ecdsa.py
// same inputs as for NIST p 256, but narrowed down to 192 bits
const pkha_input_t input = {
    .random_k = {
        { 0x9f, 0xa7, 0xa6, 0x0d, 0x8b, 0x75, 0x09, 0xf0,
          0x65, 0x9d, 0xbe, 0x3f, 0x36, 0x68, 0x03, 0xd1,
          0x06, 0x75, 0x2f, 0xc9, 0xb6, 0x8c, 0x29, 0x27 },
        24
    },
    .pkey = {
        { 0xad, 0xde, 0xbe, 0xba, 0xad, 0xde, 0xbe, 0xba,
          0xad, 0xde, 0xbe, 0xba, 0xad, 0xde, 0xbe, 0xba,
          0xad, 0xde, 0xbe, 0xba, 0xad, 0xde, 0xbe, 0xba },
        24

    },
    .hash = {
        { 0xe7, 0xb7, 0x6c, 0x95, 0x48, 0xcd, 0x4e, 0x58,
          0x33, 0x76, 0xad, 0xc5, 0x26, 0x5a, 0x97, 0x5b,
          0xce, 0x3f, 0x98, 0xaf, 0x6d, 0x1d, 0x3a, 0x67,
          0xc8, 0xe7, 0xff, 0x6a, 0x70, 0x60, 0x82, 0xd0 },
        32
    }
};
#endif

pkha_signature_t signature = { {{0}, 0}, {{0}, 0} };

/*******************************************************************************
  * @function   app_init
  * @brief      Initialization of MCU and its ports and peripherals.
  * @param      None.
  * @retval     None.
  *****************************************************************************/
static void app_init(void)
{
	/* configure peripherals */
	debug_init();
	sys_flash_init();
	crc32_enable();
	sys_time_config();

	/* configure power control */
	power_control_io_config();
	power_control_usb_timeout_config();

	/* configure input signals */
	input_signals_config();

	/* configure LED driver */
	led_driver_config();

    sys_trng_init();
    sys_ltc_init();

	debug("\nInit completed.\n");
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

	sys_msleep(100);

	return power_control_enable_regulators();
}

/*******************************************************************************
  * @function   light_reset
  * @brief      Perform light reset of the board.
  * @param      None.
  * @retval     None.
  *****************************************************************************/
static void light_reset(void)
{
	disable_irq();
	led_driver_init();
	i2c_iface_init();
	i2c_slave_init(SLAVE_I2C, &i2c_slave, MCU_I2C_ADDR,
		       LED_CONTROLLER_I2C_ADDR, 2);
	enable_irq();

	power_control_first_startup();

	led_driver_reset_pattern_start();

	sys_input_signals_init();
}

/*******************************************************************************
  * @function   error_manager
  * @brief      Handle error occuring in startup.
  * @param      err_led: LED index indicating the error
  * @retval     None.
  *****************************************************************************/
static void error_manager(unsigned led)
{
	sys_led_set_user_mode(LED_COUNT, false);
	led_set_state(LED_COUNT, false);
	led_set_color24(LED_COUNT, RED_COLOR);

	sys_msleep(300);

	led_set_state(led, true);

	sys_msleep(300);
}

void main(void)
{
	state_t next_state = POWER_ON;
	uint8_t error_counter = 0;
	int err;

	app_init();

	while (1) {
        static int counter = 0;
        if (counter == 0)
        {
            sys_ltc_pkha_sign(&nist_p_192, &input, &signature);
        }
        counter++;
		switch (next_state) {
		case POWER_ON:
			err = power_on();

			if (!err)
				next_state = LIGHT_RESET;
			else
				next_state = ERROR_STATE;
			break;

		case LIGHT_RESET:
			light_reset();

			next_state = INPUT_MANAGER;
			break;

		case HARD_RESET:
			sys_hard_reset();
			unreachable();

		case ERROR_STATE:
			error_manager(-err - 1);
			error_counter++;

			if (error_counter >= MAX_ERROR_COUNT)
				next_state = HARD_RESET;
			break;

		case INPUT_MANAGER:
			switch (sys_input_signals_poll()) {
			case INPUT_REQ_LIGHT_RESET:
				next_state = LIGHT_RESET;
				break;

			case INPUT_REQ_HARD_RESET:
				next_state = HARD_RESET;
				break;

			default:
				next_state = I2C_MANAGER;
				break;
			}
			break;

		case I2C_MANAGER:
			switch (i2c_iface_poll()) {
			case I2C_IFACE_REQ_HARD_RESET:
				next_state = HARD_RESET;
				break;

			case I2C_IFACE_REQ_BOOTLOADER:
				next_state = BOOTLOADER;
				break;

			default:
				next_state = INPUT_MANAGER;
				break;
			}
			break;

		case BOOTLOADER:
			soft_reset_to_other_program();
			break;
		}
	}
}
