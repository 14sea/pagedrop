#include <stdio.h>
static char pad[48 * 1024] = {1, 2, 3, 4};
void marker(void)
{
#if defined(__aarch64__)
	__asm__ volatile(
		"movz x0, #0x2211\n"
		"movk x0, #0x4433, lsl #16\n"
		"movk x0, #0x6655, lsl #32\n"
		"movk x0, #0x8877, lsl #48\n"
		"ret\n"
	);
#else
	__asm__ volatile(
		".byte 0x90, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0x90, 0x90\n"
		".byte 0x48, 0xb8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88\n"
	);
#endif
}
int main(void)
{
	marker();
	printf("upx-ok %d\n", pad[0]);
	return 0;
}
