#ifndef I2C_H
#define I2C_H

#include "stm32f0xx_i2c.h"
#include "stm32f0xx_rcc.h"
#include "compiler.h"
#include "bits.h"
#include "gpio.h"

typedef uint8_t i2c_nr_t;

#define I2C2_PINS_ALT_FN	1
#define I2C2_SCL_PIN		PIN(F, 6)
#define I2C2_SDA_PIN		PIN(F, 7)

#define SLAVE_I2C		2

typedef enum {
	I2C_SLAVE_READ_REQUESTED,
	I2C_SLAVE_WRITE_REQUESTED,
	I2C_SLAVE_READ_PROCESSED,
	I2C_SLAVE_WRITE_RECEIVED,
	I2C_SLAVE_STOP,
} i2c_slave_event_t;

typedef struct {
	i2c_slave_event_t state;
	uint8_t addr;
	uint8_t val;
	bool paused;
	void *priv;
	int (*cb)(void *priv, uint8_t addr, i2c_slave_event_t event, uint8_t *val);
} i2c_slave_t;

extern i2c_slave_t *i2c_slave_ptr[2];

static __force_inline I2C_TypeDef *i2c_to_plat(i2c_nr_t i2c_nr)
{
	switch (i2c_nr) {
	case 1: return I2C1;
	case 2: return I2C2;
	default: unreachable();
	}
}

static __force_inline void i2c_rcc_config(i2c_nr_t i2c_nr, bool on)
{
	switch (i2c_nr) {
	case 1:
		RCC_APB1PeriphClockCmd(RCC_APB1Periph_I2C1, on);
		break;
	case 2:
		RCC_APB1PeriphClockCmd(RCC_APB1Periph_I2C2, on);
		break;
	default:
		unreachable();
	}
}

static __force_inline uint8_t i2c_irqn(i2c_nr_t i2c_nr)
{
	switch (i2c_nr) {
	case 1: return I2C1_IRQn;
	case 2: return I2C2_IRQn;
	default: unreachable();
	}
}

static __force_inline i2c_nr_t i2c_nr_in_irq(void)
{
	switch ((__get_IPSR() & 0x3f) - 16) {
	case I2C1_IRQn: return 1;
	case I2C2_IRQn: return 2;
	default: unreachable();
	}
}

static __force_inline void i2c_init_pins(i2c_nr_t i2c_nr)
{
	compiletime_assert(i2c_nr == SLAVE_I2C, "Invalid I2C peripheral used");

	gpio_init_alts(I2C2_PINS_ALT_FN, pin_opendrain, pin_spd_1,
		       pin_nopull, I2C2_SCL_PIN, I2C2_SDA_PIN);
}

static inline void i2c_slave_init(i2c_nr_t i2c_nr, i2c_slave_t *slave,
				  uint8_t addr1, uint8_t addr2, uint8_t irq_prio)
{
	I2C_TypeDef *i2c = i2c_to_plat(i2c_nr);
	I2C_InitTypeDef init = {
		.I2C_Mode = I2C_Mode_I2C,
		.I2C_AnalogFilter = I2C_AnalogFilter_Enable,
		.I2C_DigitalFilter = 0x00,
		.I2C_OwnAddress1 = addr1 << 1,
		.I2C_Ack = I2C_Ack_Enable,
		.I2C_AcknowledgedAddress = I2C_AcknowledgedAddress_7bit,
		.I2C_Timing = 0x10800000, /* 100kHz for 48MHz system clock */
	};
	NVIC_InitTypeDef nvinit = {
		.NVIC_IRQChannel = i2c_irqn(i2c_nr),
		.NVIC_IRQChannelPriority = irq_prio,
		.NVIC_IRQChannelCmd = ENABLE,
	};

	i2c_rcc_config(i2c_nr, 0);
	I2C_DeInit(i2c);
	i2c_rcc_config(i2c_nr, 1);

	i2c_init_pins(i2c_nr);

	I2C_Init(i2c, &init);

	if (addr2) {
		I2C_OwnAddress2Config(i2c, addr2 << 1, I2C_OA2_Mask01);
		I2C_DualAddressCmd(i2c, ENABLE);
	}

	I2C_SlaveByteControlCmd(i2c, ENABLE);
	I2C_ReloadCmd(i2c, ENABLE);

	/* Address match, transfer complete, stop and transmit interrupt */
	I2C_ITConfig(i2c, I2C_IT_ADDRI | I2C_IT_ERRI | I2C_IT_STOPI, ENABLE);

	slave->state = I2C_SLAVE_STOP;
	i2c_slave_ptr[i2c_nr - 1] = slave;

	I2C_Cmd(i2c, ENABLE);
	NVIC_Init(&nvinit);
}

/* should be called only from slave callback, disable I2C interrupts
 * after end of transaction */
static __force_inline void i2c_slave_pause(i2c_nr_t i2c_nr)
{
	i2c_slave_ptr[i2c_nr - 1]->paused = 1;
}

static __force_inline void i2c_slave_resume(i2c_nr_t i2c_nr)
{
	i2c_slave_ptr[i2c_nr - 1]->paused = 0;
	i2c_to_plat(i2c_nr)->CR1 |= I2C_CR1_ADDRIE | I2C_CR1_ERRIE |
				    I2C_CR1_STOPIE;
}

static __force_inline void i2c_slave_ack(i2c_nr_t i2c_nr, bool ack)
{
	I2C_TypeDef *i2c = i2c_to_plat(i2c_nr);

	if (ack)
		i2c->CR2 &= ~I2C_CR2_NACK;
	else
		i2c->CR2 |= I2C_CR2_NACK;

	/* set NBYTES=1 to release SCL */
	i2c->CR2 = (i2c->CR2 & ~I2C_CR2_NBYTES) | FIELD_PREP(I2C_CR2_NBYTES, 1);
}

void i2c_slave_irq_handler(void);

#endif /* I2C_H */