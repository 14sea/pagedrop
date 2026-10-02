#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define PAGE 4096
#define MOVE_ADDR ((void *)0x3000000000UL)

static unsigned char *make_page(const char *marker)
{
	unsigned char *p;

	p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED)
		return NULL;
	memset(p, 0, PAGE);
	memcpy(p, marker, strlen(marker));
	return p;
}

static int dump_has(const char *marker, unsigned long want)
{
	DIR *d;
	struct dirent *de;
	int found = 0;

	d = opendir("/tmp");
	if (!d)
		return 0;
	while ((de = readdir(d))) {
		unsigned long addr, epoch;
		char path[320];
		unsigned char buf[64];
		int fd, n;

		if (sscanf(de->d_name, "%lx_%lu", &addr, &epoch) != 2)
			continue;
		if (want && addr != want)
			continue;
		snprintf(path, sizeof(path), "/tmp/%s", de->d_name);
		fd = open(path, O_RDONLY);
		if (fd < 0)
			continue;
		n = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (n < 0)
			continue;
		buf[n] = 0;
		if (memmem(buf, n, marker, strlen(marker))) {
			found = 1;
			break;
		}
	}
	closedir(d);
	return found;
}

static void *thread_page(void *arg)
{
	unsigned char *p = make_page("PBTHREAD");

	if (!p || mprotect(p, PAGE, PROT_READ | PROT_EXEC) != 0)
		return (void *)1;
	return NULL;
}

static int child_page(void)
{
	unsigned char *p;
	int fds[2];
	pid_t kid;
	char buf[64];
	ssize_t n;
	int status;

	if (pipe(fds) != 0)
		return 1;
	kid = fork();
	if (kid < 0)
		return 1;
	if (kid == 0) {
		close(fds[0]);
		prctl(PR_SET_NAME, "childx", 0, 0, 0);
		p = make_page("PBCHILD!");
		if (!p || mprotect(p, PAGE, PROT_READ | PROT_EXEC) != 0)
			_exit(1);
		dprintf(fds[1], "ok\n");
		_exit(0);
	}
	close(fds[1]);
	n = read(fds[0], buf, sizeof(buf));
	waitpid(kid, &status, 0);
	if (n <= 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return 1;
	return dump_has("PBCHILD!", 0) ? 0 : 1;
}

int main(void)
{
	unsigned char *p;
	void *moved;
	int pk, i, rc = 0;
	pthread_t th[4];

	if (prctl(PR_SET_NAME, "notme", 0, 0, 0) != 0)
		return 1;

	p = make_page("PBRENAME");
	if (!p || mprotect(p, PAGE, PROT_READ | PROT_EXEC) != 0)
		return 1;
	if (!dump_has("PBRENAME", 0)) {
		fprintf(stderr, "rename: marker not dumped\n");
		rc = 1;
	}

	if (child_page() != 0) {
		fprintf(stderr, "child: marker not dumped\n");
		rc = 1;
	}

	p = make_page("PBMOVE!!");
	if (!p || mprotect(p, PAGE, PROT_READ | PROT_EXEC) != 0)
		return 1;
	moved = mremap(p, PAGE, PAGE, MREMAP_MAYMOVE | MREMAP_FIXED, MOVE_ADDR);
	if (moved == MAP_FAILED) {
		perror("mremap");
		return 1;
	}
	if (!dump_has("PBMOVE!!", (unsigned long)moved)) {
		fprintf(stderr, "mremap: marker missing at %p\n", moved);
		rc = 1;
	}

	p = make_page("PBPKEY!!");
	if (!p)
		return 1;
	pk = syscall(SYS_pkey_alloc, 0, 0);
	if (pk < 0) {
		syscall(SYS_pkey_mprotect, p, PAGE, PROT_READ | PROT_EXEC, 0);
		if (!dump_has("PBPKEY!!", 0)) {
			fprintf(stderr, "pkey: marker not dumped (%s)\n", strerror(errno));
			rc = 1;
		}
	} else if (syscall(SYS_pkey_mprotect, p, PAGE, PROT_READ | PROT_EXEC, pk) != 0) {
		perror("pkey_mprotect");
		rc = 1;
	} else if (!dump_has("PBPKEY!!", 0)) {
		fprintf(stderr, "pkey: marker not dumped\n");
		rc = 1;
	}

	for (i = 0; i < 4; i++) {
		if (pthread_create(&th[i], NULL, thread_page, NULL) != 0)
			return 1;
	}
	for (i = 0; i < 4; i++) {
		void *tr = NULL;
		pthread_join(th[i], &tr);
		if (tr)
			rc = 1;
	}
	if (!dump_has("PBTHREAD", 0)) {
		fprintf(stderr, "threads: marker not dumped\n");
		rc = 1;
	}

	if (rc == 0)
		printf("capture ok\n");
	return rc;
}
