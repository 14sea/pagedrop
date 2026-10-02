#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

static int ready(unsigned long want, const unsigned char *needle, size_t nlen)
{
	DIR *d = opendir("/tmp");
	struct dirent *de;
	int ok = 0;

	if (!d)
		return 0;
	while ((de = readdir(d))) {
		unsigned long addr, epoch;
		char path[320];
		unsigned char buf[16];
		int fd;

		if (sscanf(de->d_name, "%lx_%lu", &addr, &epoch) != 2)
			continue;
		if (addr != want)
			continue;
		snprintf(path, sizeof(path), "/tmp/%s", de->d_name);
		fd = open(path, O_RDONLY);
		if (fd < 0)
			continue;
		if (read(fd, buf, nlen) == (ssize_t)nlen && memcmp(buf, needle, nlen) == 0)
			ok = 1;
		close(fd);
		if (ok)
			break;
	}
	closedir(d);
	return ok;
}

int main(int argc, char **argv)
{
	unsigned long want = 0x3000000000UL;
	const unsigned char needle[] = "PBMOVE!!";
	pid_t pid;
	int status, found = 0;

	if (argc < 2)
		return 2;
	pid = fork();
	if (pid == 0) {
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		raise(SIGSTOP);
		execvp(argv[1], argv + 1);
		_exit(127);
	}
	waitpid(pid, &status, 0);
	ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
	ptrace(PTRACE_SYSCALL, pid, 0, 0);
	while (waitpid(pid, &status, 0) > 0 && !WIFEXITED(status) && !WIFSIGNALED(status)) {
		int sig = WIFSTOPPED(status) ? WSTOPSIG(status) : 0;

		if (ready(want, needle, 8)) {
			uint64_t ent = 0;
			unsigned char live[8];
			struct iovec loc = {live, 8}, rem = {(void *)want, 8};
			char pm[64];
			int fd;

			snprintf(pm, sizeof(pm), "/proc/%d/pagemap", pid);
			fd = open(pm, O_RDONLY);
			if (fd >= 0) {
				pread(fd, &ent, 8, (want / 4096) * 8);
				close(fd);
			}
			process_vm_readv(pid, &loc, 1, &rem, 1, 0);
			printf("va=%lx present=%d pfn=%lx live=%s\n", want,
			       (int)((ent >> 63) & 1),
			       (unsigned long)(ent & ((1ULL << 55) - 1)),
			       memcmp(live, needle, 8) == 0 ? "match" : "MISMATCH");
			found = ((ent >> 63) & 1) && memcmp(live, needle, 8) == 0;
			break;
		}
		if (sig == SIGTRAP || sig == SIGSTOP || sig == (SIGTRAP | 0x80))
			sig = 0;
		ptrace(PTRACE_SYSCALL, pid, 0, sig);
	}
	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);
	return found ? 0 : 1;
}
