/**
 ******************************************************************************
 * @file    debounce.c
 * @author  CZ.NIC, z.s.p.o.
 * @date    21-July-2015
 * @brief   Debounce switches and inputs from PG signals
 ******************************************************************************
 ******************************************************************************
 **/
#include "stm32f0xx.h"
#include "debounce.h"
#include "stm32f0xx_conf.h"

enum input_mask {
    MAN_RES_MASK                    = 0x0001,
    SYSRES_OUT_MASK                 = 0x0002,
    DBG_RES_MASK                    = 0x0004,
    MRES_MASK                       = 0x0008,
    PG_5V_MASK                      = 0x0010,
    PG_3V3_MASK                     = 0x0020,
    PG_1V35_MASK                    = 0x0040,
    PG_4V5_MASK                     = 0x0080,
    PG_1V8_MASK                     = 0x0100,
    PG_1V5_MASK                     = 0x0200,
    PG_1V2_MASK                     = 0x0400,
    PG_VTT_MASK                     = 0x0800,
    USB30_OVC_MASK                  = 0x1000,
    USB31_OVC_MASK                  = 0x2000,
    RTC_ALARM_MASK                  = 0x4000,
    LED_BRT_MASK                    = 0x8000,
};

struct input_sig debounce_input_signal;

#define MAX_INPUT_STATES            3
static uint16_t debounced_state;
static uint16_t port_state[MAX_INPUT_STATES];


#define  DEBOUNCE_TIM_PERIODE       (200 - 1)//200 = 5ms
#define  DEBOUNCE_TIM_PRESCALER     (200 - 1)

/*******************************************************************************
  * @function   debounce_timer_config
  * @brief      Timer configuration for debouncing. Regulary interrupt every 5ms.
  * @param      None.
  * @retval     None.
  *****************************************************************************/
static void debounce_timer_config(void)
{
    TIM_TimeBaseInitTypeDef  TIM_TimeBaseStructure;
    NVIC_InitTypeDef NVIC_InitStructure;

    // Clock enable
    RCC_APB2PeriphClockCmd(RCC_APB2Periph_TIM16, ENABLE);

    /* Time base configuration */
    TIM_TimeBaseStructure.TIM_Period = DEBOUNCE_TIM_PERIODE;
    TIM_TimeBaseStructure.TIM_Prescaler = DEBOUNCE_TIM_PRESCALER;
    TIM_TimeBaseStructure.TIM_ClockDivision = 0;
    TIM_TimeBaseStructure.TIM_CounterMode = TIM_CounterMode_Up;
    TIM_TimeBaseInit(DEBOUNCE_TIMER, &TIM_TimeBaseStructure);

    TIM_ARRPreloadConfig(DEBOUNCE_TIMER, ENABLE);
    /* TIM Interrupts enable */
    TIM_ITConfig(DEBOUNCE_TIMER, TIM_IT_Update, ENABLE);

    /* TIM enable counter */
    TIM_Cmd(DEBOUNCE_TIMER, ENABLE);

    NVIC_InitStructure.NVIC_IRQChannel = TIM16_IRQn;
    NVIC_InitStructure.NVIC_IRQChannelPriority = 0x03;
    NVIC_InitStructure.NVIC_IRQChannelCmd = ENABLE;
    NVIC_Init(&NVIC_InitStructure);
}

/*******************************************************************************
  * @function   debounce_input_timer_handler
  * @brief      Main debounce function. Called in timer interrupt handler.
  * @param      None.
  * @retval     None.
  *****************************************************************************/
void debounce_input_timer_handler(void)
{
    static uint16_t idx;

    port_state[idx] = ~(GPIO_ReadInputData(GPIOB)); //read whole port
    idx++;

    if (idx >= MAX_INPUT_STATES)
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
    uint16_t i, port_changed;
    static uint16_t last_debounce_state;
    struct input_sig *input_signal_state = &debounce_input_signal;

    last_debounce_state = debounced_state;

    debounced_state = 0xFFFF; //init for calculation - include of all 16 inputs

    for (i = 0; i < MAX_INPUT_STATES; i++)
    {
        debounced_state = debounced_state & port_state[i];
    }

    port_changed = (debounced_state ^ last_debounce_state) & debounced_state;

    if (port_changed & MAN_RES_MASK)
        input_signal_state->man_res = 1;

    if (port_changed & SYSRES_OUT_MASK)
        input_signal_state->sysres_out = 1;

    if (port_changed & DBG_RES_MASK)
        input_signal_state->dbg_res = 1;

    if (port_changed & MRES_MASK)
        input_signal_state->m_res = 1;

    if (port_changed & PG_5V_MASK)
        input_signal_state->pg_5v = 1;

    if (port_changed & PG_3V3_MASK)
        input_signal_state->pg_3v3 = 1;

    if (port_changed & PG_1V35_MASK)
        input_signal_state->pg_1v35 = 1;

    if (port_changed & PG_4V5_MASK)
        input_signal_state->pg_4v5 = 1;

    if (port_changed & PG_1V8_MASK)
        input_signal_state->pg_1v8 = 1;

    if (port_changed & PG_1V5_MASK)
        input_signal_state->pg_1v5 = 1;

    if (port_changed & PG_1V2_MASK)
        input_signal_state->pg_1v2 = 1;

    if (port_changed & PG_VTT_MASK)
        input_signal_state->pg_vtt = 1;

    if (port_changed & USB30_OVC_MASK)
        input_signal_state->usb30_ovc = 1;

    if (port_changed & USB31_OVC_MASK)
        input_signal_state->usb31_ovc = 1;

    if (port_changed & RTC_ALARM_MASK)
        input_signal_state->rtc_alarm = 1;

    if (port_changed & LED_BRT_MASK)
        input_signal_state->led_brt = 1;
}

/*******************************************************************************
  * @function   debounce_config
  * @brief      Debouncer configuration.
  * @param      None.
  * @retval     None.
  *****************************************************************************/
void debounce_config(void)
{
    debounce_timer_config();
}