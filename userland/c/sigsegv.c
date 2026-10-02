#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define PAGE 4096

typedef int func(void);

int main(void)
{
#if defined(__aarch64__)
	static const unsigned char shellcode[] = {
		0x20, 0x42, 0x84, 0xd2,
		0x60, 0x86, 0xa8, 0xf2,
		0xa0, 0xca, 0xcc, 0xf2,
		0xe0, 0x0e, 0xf1, 0xf2,
		0xc0, 0x03, 0x5f, 0xd6
	};
	const size_t sc_len = sizeof(shellcode);
	uint32_t *words;
	size_t i;
#else
	static const char shellcode[] =
		"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff"
		"\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";
	const size_t sc_len = sizeof(shellcode) - 1;
#endif
	char *region;

	printf("Start of sigsegv.out\n");

	region = mmap((void *)(PAGE * (1UL << 20)), 2 * PAGE,
		      PROT_READ | PROT_WRITE | PROT_EXEC,
		      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
		return 1;
	}

#if defined(__aarch64__)
	words = (uint32_t *)region;
	for (i = 0; i < (2 * PAGE) / sizeof(*words); i++)
		words[i] = 0xd503201f;
	words[PAGE / sizeof(*words)] = 0xd65f03c0;
#else
	memset(region, 0x90, PAGE);
	memset(region + PAGE, 0x90, PAGE);
	region[PAGE] = 0xc3;
#endif
	memcpy(region + PAGE - sc_len, shellcode, sc_len);

	((func *)0x100000000)();
	return 0;
}
