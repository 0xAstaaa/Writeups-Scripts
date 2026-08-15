#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
	char *argv[] = { "/home/ctf/exploit", NULL };
	char *envp[] = { "PATH=/bin:/sbin:/usr/bin:/usr/sbin", NULL };

	if (setgid(1000) != 0 || setuid(1000) != 0) {
		perror("drop privileges");
		return 111;
	}

	execve(argv[0], argv, envp);
	perror("execve exploit");
	return errno ? errno : 1;
}
