#ifndef MEMORY_LAYOUT_H
#define MEMORY_LAYOUT_H

#define BOOTLOADER_BEGIN	0x08000000
#define BOOTLOADER_VERSION_POS	(BOOTLOADER_BEGIN + ISR_VECTOR_LENGTH)
#define BOOTLOADER_FEATURES	(BOOTLOADER_VERSION_POS + 20)
#define BOOTLOADER_MAX_SIZE	APPLICATION_OFFSET

#define APPLICATION_BEGIN	(BOOTLOADER_BEGIN + APPLICATION_OFFSET)
#define APPLICATION_CRCSUM	(APPLICATION_BEGIN + ISR_VECTOR_LENGTH)
#define APPLICATION_FEATURES	(APPLICATION_CRCSUM + 8)
#define APPLICATION_END		0x08008000
#define APPLICATION_MAX_SIZE	(APPLICATION_END - APPLICATION_BEGIN)

#define RAM_BEGIN		0x20000000
#define RAM_LENGTH		0x2000

#endif /* MEMORY_LAYOUT_H */
