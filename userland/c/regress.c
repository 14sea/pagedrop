#include <stdio.h>

static char pad[48 * 1024] = {1, 2, 3, 4};

static int mix(int x)
{
	return (x * 17) ^ 0x5a5a;
}

int main(void)
{
	int v;

	v = mix(13);
	printf("regress-ok %d %d\n", pad[0], v);
	return v == 23175 ? 0 : 1;
}
