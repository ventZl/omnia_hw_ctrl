#if PRIVILEGES

#include "cpu.h"
#include "svc.h"
#include "input.h"
#include "signal.h"
#include "led_driver.h"
#include "clock.h"
#include "i2c_slave.h"
#include "irq.h"
#include "time.h"
#include "led_driver.h"
#include "flash.h"
#include "firmware_flash.h"
#include "reset.h"
#include "timer.h"
#include "watchdog.h"
#include "poweroff.h"
#include "debug.h"
#ifdef MKL81
#include "trng.h"
#include "ltc.h"
#endif

#pragma GCC optimize ("O3")

void __irq svc_handler(void)
{
	exception_frame_t *frame = (void *)get_psp();
	svc_t svc = *(uint8_t *)(frame->pc - 2);
	uint32_t arg1 = frame->r0;
	uint32_t arg2 = frame->r1;
	uint32_t arg3 = frame->r2;

	/* input_signals_poll() is the most frequent syscall */
	if (likely(svc == SYS_input_signals_poll)) {
		frame->r0 = input_signals_poll();
	} else switch (svc) {
	case SYS_sigreturn:
		sigreturn();
		break;
	case SYS_button_counter_decrease:
		button_counter_decrease(arg1);
		break;
	case SYS_button_set_user_mode:
		button_set_user_mode(arg1);
		break;
	case SYS_input_signals_init:
		input_signals_init();
		break;
	case SYS_led_driver_set_brightness:
		led_driver_set_brightness(arg1);
		break;
	case SYS_led_driver_overwrite_brightness:
		led_driver_overwrite_brightness(arg1, arg2);
		break;
	case SYS_led_set_user_mode:
		led_set_user_mode(arg1, arg2);
		break;
	case SYS_led_set_state_user:
		led_set_state_user(arg1, arg2);
		break;
	case SYS_clk_config:
		clk_config(arg1, arg2);
		break;
	case SYS_enable_irq_with_prio:
		enable_irq_with_prio(arg1, arg2);
		break;
	case SYS_time_config:
		time_config();
		break;
	case SYS_msleep:
		msleep(arg1);
		break;
	case SYS_watchdog_enable:
		watchdog_enable(arg1);
		break;
	case SYS_watchdog_set_timeout:
		watchdog_set_timeout(arg1);
		break;
	case SYS_flash_init:
		flash_init();
		break;
	case SYS_plat_firmware_flash_finish:
		plat_firmware_flash_finish((void *)arg1, (void *)arg2);
		break;
	case SYS_plat_soft_reset_to_other_program:
		plat_soft_reset_to_other_program();
		break;
	case SYS_hard_reset:
		hard_reset();
		break;
	case SYS_poweroff:
		poweroff(arg1, arg2);
		break;

/* Following code is using TRNG and LTC peripheral of MKL81
 * and therefore syscalls are only available there */
#ifdef MKL81
    case SYS_trng_init:
        trng_init();
        break;
    case SYS_trng_ready:
        frame->r0 = trng_ready();
        break;
    case SYS_trng_entropy:
        frame->r0 = trng_entropy((uint32_t *) arg1);
        break;
    case SYS_ltc_init:
        ltc_init();
        break;
    case SYS_ltc_sha_start:
        ltc_sha_start((ltc_sha_mode_t) arg1, (uint32_t) arg2);
        return;
    case SYS_ltc_sha_data:
        frame->r0 = ltc_sha_data((uint8_t *) arg1, (uint16_t) arg2);
        break;
    case SYS_ltc_sha_finish:
        frame->r0 = ltc_sha_finish((uint8_t *) arg1);
        break;
    case SYS_ltc_pkha_sign:
        frame->r0 = ltc_pkha_sign((const pkha_curve_t *) arg1, (const pkha_sign_input_t *) arg2,
                                  (pkha_signature_t *) arg3);
        break;
    case SYS_ltc_pkha_verify:
        frame->r0 = ltc_pkha_verify((const pkha_curve_t *) arg1, (const pkha_verify_input_t *) arg2,
                                    (const pkha_signature_t *) arg3);
        break;
    case SYS_ltc_pkha_validate_publickey:
        frame->r0 = ltc_pkha_validate_publickey((const pkha_curve_t *) arg1, (const pkha_verify_input_t *) arg2);
        break;
#endif

	default:
		debug("unhandled svc(%u, %#10x, %#10x)\n", svc, arg1, arg2);
		break;
	}
}

#endif /* PRIVILEGES */
