#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define PAGE 4096
#define EPOCH_ADDR 0x250000000UL
#define FAIL_ADDR 0x230000000UL
#define TAG_ADDR 0x240000000UL
#define READ_DATA 0x260000000UL
#define READ_CODE 0x261000000UL
#define TAG_BYTE 0x5aUL

static sigjmp_buf fault_env;
static volatile int faulted;

static void on_fault(int sig)
{
	(void)sig;
	faulted = 1;
	siglongjmp(fault_env, 1);
}

static void arm_fault(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_fault;
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGILL, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);
	alarm(10);
}

static void plant(void *p, const char *mark)
{
	memcpy((unsigned char *)p + 16, mark, 8);
#if defined(__aarch64__)
	*(uint32_t *)p = 0xd65f03c0;
#else
	*(unsigned char *)p = 0xc3;
#endif
}

static int file_has(const char *path, const char *mark, int n)
{
	unsigned char buf[64];
	int fd;
	int got;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return 0;
	got = read(fd, buf, sizeof(buf));
	close(fd);
	if (got < 16 + n)
		return 0;
	return memcmp(buf + 16, mark, n) == 0;
}

static int dump_exact(unsigned long want, const char *mark)
{
	DIR *d;
	struct dirent *de;
	int n = strlen(mark);
	int found = 0;

	d = opendir("/tmp");
	if (!d)
		return 0;
	while ((de = readdir(d))) {
		unsigned long addr, epoch;
		char path[320];

		if (sscanf(de->d_name, "%lx_%lu", &addr, &epoch) != 2)
			continue;
		if (want && addr != want)
			continue;
		snprintf(path, sizeof(path), "/tmp/%s", de->d_name);
		if (file_has(path, mark, n)) {
			found = 1;
			break;
		}
	}
	closedir(d);
	return found;
}

static int count_mark(const char *mark)
{
	DIR *d;
	struct dirent *de;
	int n = strlen(mark);
	int count = 0;

	d = opendir("/tmp");
	if (!d)
		return 0;
	while ((de = readdir(d))) {
		unsigned long addr, epoch;
		char path[320];

		if (sscanf(de->d_name, "%lx_%lu", &addr, &epoch) != 2)
			continue;
		snprintf(path, sizeof(path), "/tmp/%s", de->d_name);
		if (file_has(path, mark, n))
			count++;
	}
	closedir(d);
	return count;
}

static void *map_fixed(unsigned long addr, int prot)
{
	void *p;

	p = mmap((void *)addr, PAGE, prot, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (p == MAP_FAILED)
		return NULL;
	return p;
}

static int call_ok(void *p)
{
	faulted = 0;
	if (sigsetjmp(fault_env, 1) != 0)
		return 0;
	((void (*)(void))p)();
	return !faulted;
}

static int do_epoch(void)
{
	void *p;

	arm_fault();
	p = map_fixed(EPOCH_ADDR, PROT_READ | PROT_WRITE | PROT_EXEC);
	if (!p) {
		perror("epoch mmap");
		return 1;
	}
	plant(p, "EPOCH-A!");
	if (!call_ok(p) || !dump_exact(EPOCH_ADDR, "EPOCH-A!")) {
		fprintf(stderr, "epoch: first dump missing\n");
		return 1;
	}
	plant(p, "EPOCH-B!");
	if (!call_ok(p) || !dump_exact(EPOCH_ADDR, "EPOCH-B!")) {
		fprintf(stderr, "epoch: second dump missing\n");
		return 1;
	}
	if (count_mark("EPOCH-A!") < 1 || count_mark("EPOCH-B!") < 1) {
		fprintf(stderr, "epoch: old dump was replaced\n");
		return 1;
	}
	printf("epoch ok\n");
	return 0;
}

static int do_flip(void)
{
	unsigned char *p;

	p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) {
		perror("flip mmap");
		return 1;
	}
	memcpy(p + 16, "FLIP-OLD", 8);
	if (mprotect(p, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("flip rx");
		return 1;
	}
	if (!dump_exact(0, "FLIP-OLD")) {
		fprintf(stderr, "flip: old marker not dumped\n");
		return 1;
	}
	if (mprotect(p, PAGE, PROT_READ | PROT_WRITE) != 0) {
		perror("flip rw");
		return 1;
	}
	memcpy(p + 16, "FLIP-NEW", 8);
	if (mprotect(p, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("flip rx2");
		return 1;
	}
	if (!dump_exact(0, "FLIP-NEW") || !dump_exact(0, "FLIP-OLD")) {
		fprintf(stderr, "flip: expected both markers\n");
		return 1;
	}
	printf("flip ok\n");
	return 0;
}

static int do_fail(void)
{
	void *p;
	char *argv[] = {"missing", NULL};
	char *envp[] = {NULL};

	arm_fault();
	p = map_fixed(FAIL_ADDR, PROT_READ | PROT_WRITE | PROT_EXEC);
	if (!p) {
		perror("fail mmap");
		return 1;
	}
	plant(p, "KEEPME!!");
	execve("/tmp/missing-exectest", argv, envp);
	execve("/tmp/missing-other", argv, envp);
	if (!call_ok(p) || !dump_exact(FAIL_ADDR, "KEEPME!!")) {
		fprintf(stderr, "execfail: tracking dropped\n");
		return 1;
	}
	printf("execfail ok\n");
	return 0;
}

static int do_payload(void)
{
	const char *mark = getenv("PB_MARK");
	unsigned char *p;

	if (!mark || strlen(mark) != 8)
		mark = "PBPAYLD!";
	p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED)
		return 1;
	memcpy(p + 16, mark, 8);
	if (mprotect(p, PAGE, PROT_READ | PROT_EXEC) != 0)
		return 1;
	if (!dump_exact(0, mark)) {
		fprintf(stderr, "payload: %s not dumped\n", mark);
		return 1;
	}
	printf("payload %s\n", mark);
	return 0;
}

static int trace_has(unsigned long va)
{
	FILE *f;
	char line[128];
	int found = 0;

	f = fopen("/tmp/pagedrop.trace", "r");
	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f)) {
		unsigned long ip, data;
		unsigned long epoch;

		if (sscanf(line, "%lx %lx %lu", &ip, &data, &epoch) != 3)
			continue;
		if (data == va) {
			found = 1;
			break;
		}
	}
	fclose(f);
	return found;
}

static int do_read(void)
{
	unsigned char *data;
	unsigned char *code;
	unsigned char buf[16];
	int fd;
	DIR *d;
	struct dirent *de;
	int dumped = 0;

	data = map_fixed(READ_DATA, PROT_READ | PROT_WRITE);
	code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	if (!data || !code) {
		perror("read mmap");
		return 1;
	}
	memcpy(data, "BYTECODE", 8);
#if defined(__aarch64__)
	{
		uint32_t *w = (uint32_t *)code;

		w[0] = 0xd2800001;
		w[1] = 0xf2ac0001;
		w[2] = 0xf2c00041;
		w[3] = 0xf9400020;
		w[4] = 0xd65f03c0;
	}
#else
	{
		unsigned char stub[] = {
			0x48, 0xb8, 0x00, 0x00, 0x00, 0x60, 0x02, 0x00, 0x00, 0x00,
			0x48, 0x8b, 0x00,
			0xc3
		};
		memcpy(code, stub, sizeof(stub));
	}
#endif
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("read rx");
		return 1;
	}
	arm_fault();
	if (!call_ok(code)) {
		fprintf(stderr, "read: load fault was not swallowed\n");
		return 1;
	}
	if (!trace_has(READ_DATA)) {
		fprintf(stderr, "read: trace missing\n");
		return 1;
	}
	d = opendir("/tmp");
	if (!d)
		return 1;
	while ((de = readdir(d))) {
		unsigned long addr, epoch;
		char path[320];

		if (sscanf(de->d_name, "%lx_%lu", &addr, &epoch) != 2)
			continue;
		if (addr != READ_DATA)
			continue;
		snprintf(path, sizeof(path), "/tmp/%s", de->d_name);
		fd = open(path, O_RDONLY);
		if (fd < 0)
			continue;
		if (read(fd, buf, 8) == 8 && memcmp(buf, "BYTECODE", 8) == 0)
			dumped = 1;
		close(fd);
	}
	closedir(d);
	if (!dumped) {
		fprintf(stderr, "read: data page not dumped\n");
		return 1;
	}
	printf("read ok\n");
	return 0;
}

static int do_execve(void)
{
	char *argv[] = {"notme", NULL};
	char *envp[] = {"PB_MARK=PBEXECVE", NULL};

	execve("/tmp/pbmatch/notme", argv, envp);
	perror("execve");
	return 1;
}

static int do_execveat(void)
{
	char *argv[] = {"notme", NULL};
	char *envp[] = {"PB_MARK=PBEXECAT", NULL};
	int fd;

	fd = open("/tmp/pbmatch/notme", O_RDONLY);
	if (fd < 0) {
		perror("open payload");
		return 1;
	}
	syscall(SYS_execveat, fd, "", argv, envp, AT_EMPTY_PATH);
	perror("execveat");
	return 1;
}

#if defined(__aarch64__)
static int do_tag(void)
{
	unsigned char *p;
	unsigned char *tagged;

	arm_fault();
	p = map_fixed(TAG_ADDR, PROT_READ | PROT_WRITE | PROT_EXEC);
	if (!p) {
		perror("tag mmap");
		return 1;
	}
	tagged = (unsigned char *)(TAG_ADDR | (TAG_BYTE << 56));
	if (sigsetjmp(fault_env, 1) != 0) {
		fprintf(stderr, "tag: fault was not swallowed\n");
		return 1;
	}
	plant(tagged, "TAGGED!!");
	if (!call_ok(p) || !dump_exact(TAG_ADDR, "TAGGED!!")) {
		fprintf(stderr, "tag: untagged dump missing\n");
		return 1;
	}
	if (dump_exact(TAG_ADDR | (TAG_BYTE << 56), "TAGGED!!")) {
		fprintf(stderr, "tag: dumped under the tagged address\n");
		return 1;
	}
	printf("tag ok\n");
	return 0;
}
#endif

static int is_payload(const char *argv0)
{
	const char *base = strrchr(argv0, '/');

	base = base ? base + 1 : argv0;
	return strcmp(base, "notme") == 0;
}

int main(int argc, char **argv)
{
	if (argc < 1)
		return 2;
	if (is_payload(argv[0]))
		return do_payload();
	if (argc < 2)
		return 2;
	if (!strcmp(argv[1], "epoch"))
		return do_epoch();
	if (!strcmp(argv[1], "flip"))
		return do_flip();
	if (!strcmp(argv[1], "fail"))
		return do_fail();
	if (!strcmp(argv[1], "read"))
		return do_read();
	if (!strcmp(argv[1], "execve"))
		return do_execve();
	if (!strcmp(argv[1], "execveat"))
		return do_execveat();
#if defined(__aarch64__)
	if (!strcmp(argv[1], "tag"))
		return do_tag();
#endif
	fprintf(stderr, "usage: extra epoch|flip|fail|read|execve|execveat|tag\n");
	return 2;
}
