/**
 ******************************************************************************
 * @file    main.c
 * @author  CZ.NIC, z.s.p.o.
 * @date    21-July-2015
 * @brief   Main program body
 ******************************************************************************
 ******************************************************************************
 **/

/* Includes ------------------------------------------------------------------*/
#include "stm32f0xx.h"
#include "stm32f0xx_conf.h"
#include "debounce.h"
#include "delay.h"
#include "led_driver.h"
#include "power_control.h"

/*******************************************************************************
 * @brief  Main program.
 * @param  None
 * @retval None
 ******************************************************************************/
int main(void)
{
    RCC_ClocksTypeDef RCC_Clocks;

    SystemInit();
    delay_systimer_config();
    power_control_io_config();
    power_control_enable_regulator();

    debounce_config();
    led_driver_config();

    RCC_GetClocksFreq(&RCC_Clocks); //just for debugging - check frequency value

    while(1)
    {
    }
}