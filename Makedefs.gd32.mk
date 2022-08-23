SRCS_PLAT_gd32	= $(wildcard src/platform/gd32/*.c)
SRCS_PLAT_gd32	+= src/platform/gd32/gd_lib/src/gd32f1x0_misc.c
SRCS_PLAT_gd32	+= src/platform/gd32/gd_lib/src/gd32f1x0_fmc.c

ISR_VECTOR_LENGTH_gd32	= 0x110
APP_POS_gd32		= 0x2C00
CSUM_POS_gd32		= $(ISR_VECTOR_LENGTH_gd32)

CPPFLAGS_gd32	= -DGD32F1x0 -DGD32F130_150 -DMCU_TYPE=GD32
CPPFLAGS_gd32	+= -DSYS_CORE_FREQ=72000000U
CPPFLAGS_gd32	+= -DAPPLICATION_OFFSET=$(APP_POS_gd32) -DISR_VECTOR_LENGTH=$(ISR_VECTOR_LENGTH_gd32)
CPPFLAGS_gd32	+= -Isrc/platform/gd32
CPPFLAGS_gd32	+= -Isrc/platform/gd32/cmsis
CPPFLAGS_gd32	+= -Isrc/platform/gd32/gd_lib/inc

CFLAGS_gd32	= -mcpu=cortex-m3 -mthumb -mlittle-endian

VARIANTS_gd32		= rev23 rev32
CPPFLAGS_gd32-rev23	= -DOMNIA_BOARD_REVISION=23 -DUSER_REGULATOR_ENABLED=0
CPPFLAGS_gd32-rev32	= -DOMNIA_BOARD_REVISION=32 -DUSER_REGULATOR_ENABLED=0

$(eval $(call PlatBuild,gd32))