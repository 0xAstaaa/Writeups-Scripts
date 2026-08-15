#ifndef ABYSS_ORACLE_H
#define ABYSS_ORACLE_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define ABYSS_DEVICE_NAME "abyss_oracle"
#define ABYSS_IOCTL_BASE 0xA8

#define ABYSS_MAX_OBJECTS 0x40
#define ABYSS_DATA_MAX 0x80

#define ABYSS_CAP_READ   (1ULL << 0)
#define ABYSS_CAP_WRITE  (1ULL << 1)
#define ABYSS_CAP_DUP    (1ULL << 2)
#define ABYSS_CAP_LINK   (1ULL << 3)
#define ABYSS_CAP_REVOKE (1ULL << 4)
#define ABYSS_CAP_DEBUG  (1ULL << 5)

enum abyss_kind {
	ABYSS_KIND_NOTE = 0x1337,
	ABYSS_KIND_GATE = 0x4142,
};

enum abyss_state {
	ABYSS_NEW = 1,
	ABYSS_SEALED = 2,
	ABYSS_LINKED = 3,
	ABYSS_REVOKED = 4,
};

struct abyss_create_req {
	__u32 slot;
	__u32 size;
	__u64 caps;
	__u64 user_buf;
};

struct abyss_io_req {
	__u32 slot;
	__u32 size;
	__u64 offset;
	__u64 user_buf;
};

struct abyss_dup_req {
	__u32 src;
	__u32 dst;
	__u64 mask;
};

struct abyss_link_req {
	__u32 left;
	__u32 right;
	__u32 out;
	__u32 reserved;
};

struct abyss_seek_req {
	__u32 slot;
	__u32 reserved;
	__u64 encoded_ptr;
	__u64 size;
};

struct abyss_leak_req {
	__u32 slot;
	__u32 reserved;
	__u64 value0;
	__u64 value1;
	__u64 value2;
	__u64 value3;
};

#define ABYSS_IOC_CREATE _IOW(ABYSS_IOCTL_BASE, 0x01, struct abyss_create_req)
#define ABYSS_IOC_SEAL   _IOW(ABYSS_IOCTL_BASE, 0x02, __u32)
#define ABYSS_IOC_DUP    _IOW(ABYSS_IOCTL_BASE, 0x03, struct abyss_dup_req)
#define ABYSS_IOC_LINK   _IOW(ABYSS_IOCTL_BASE, 0x04, struct abyss_link_req)
#define ABYSS_IOC_REVOKE _IOW(ABYSS_IOCTL_BASE, 0x05, __u32)
#define ABYSS_IOC_READ   _IOWR(ABYSS_IOCTL_BASE, 0x06, struct abyss_io_req)
#define ABYSS_IOC_WRITE  _IOW(ABYSS_IOCTL_BASE, 0x07, struct abyss_io_req)
#define ABYSS_IOC_SEEK   _IOW(ABYSS_IOCTL_BASE, 0x08, struct abyss_seek_req)
#define ABYSS_IOC_LEAK   _IOWR(ABYSS_IOCTL_BASE, 0x09, struct abyss_leak_req)
#define ABYSS_IOC_FLUSH  _IO(ABYSS_IOCTL_BASE, 0x0a)

#endif
