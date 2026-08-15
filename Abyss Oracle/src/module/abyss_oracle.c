#include <linux/cdev.h>
#include <linux/cred.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include "../include/abyss_oracle.h"

#define ABYSS_NAME "abyss_oracle"
#define ABYSS_OBJ_SIZE 0x100
#define ABYSS_FREED_RING 0x20

struct abyss_file;

struct abyss_ops {
	u64 (*describe)(void *obj);
};

struct abyss_note {
	u32 kind;
	u32 state;
	refcount_t refs;
	u64 salt;
	u64 caps;
	u64 cookie;
	u64 encoded_data;
	u64 size;
	u8 data[ABYSS_DATA_MAX];
	u8 pad[0x58];
};

struct abyss_gate {
	u32 kind;
	u32 state;
	refcount_t refs;
	u64 salt;
	u64 caps;
	u64 cookie;
	u64 encoded_target;
	u64 target_size;
	const struct abyss_ops *ops;
	void *anchor;
	u8 memo[0x90];
};

struct abyss_handle {
	void *ptr;
	u32 kind;
	u32 borrowed;
};

struct abyss_file {
	struct mutex lock;
	u64 key;
	u64 cookie;
	struct abyss_handle handles[ABYSS_MAX_OBJECTS];
	void *quarantine[ABYSS_FREED_RING];
	u32 qpos;
};

static dev_t abyss_dev;
static struct cdev abyss_cdev;
static struct class *abyss_class;
static struct kmem_cache *abyss_cache;

static u64 abyss_note_desc(void *obj)
{
	struct abyss_note *note = obj;

	return note->salt ^ note->size ^ note->caps;
}

static u64 abyss_gate_desc(void *obj)
{
	struct abyss_gate *gate = obj;

	return gate->salt ^ gate->target_size ^ (u64)gate->anchor;
}

static const struct abyss_ops abyss_note_ops = {
	.describe = abyss_note_desc,
};

static const struct abyss_ops abyss_gate_ops = {
	.describe = abyss_gate_desc,
};

static bool abyss_bad_slot(u32 slot)
{
	return slot >= ABYSS_MAX_OBJECTS;
}

static u64 abyss_encode(struct abyss_file *ctx, void *ptr, u64 salt)
{
	return ((u64)ptr) ^ ctx->key ^ rol64(salt, 17);
}

static void *abyss_decode(struct abyss_file *ctx, u64 encoded, u64 salt)
{
	return (void *)(encoded ^ ctx->key ^ rol64(salt, 17));
}

static bool abyss_kernelish(unsigned long addr)
{
	if (addr < PAGE_OFFSET)
		return false;
	if (addr & 7)
		return false;
	return true;
}

static bool abyss_textish(unsigned long addr)
{
	return addr >= 0xffffffff80000000UL;
}

static void abyss_put_quarantine(struct abyss_file *ctx, void *ptr)
{
	void *old = ctx->quarantine[ctx->qpos % ABYSS_FREED_RING];

	if (old)
		kmem_cache_free(abyss_cache, old);
	ctx->quarantine[ctx->qpos % ABYSS_FREED_RING] = ptr;
	ctx->qpos++;
}

static void abyss_flush_quarantine(struct abyss_file *ctx)
{
	u32 i;

	for (i = 0; i < ABYSS_FREED_RING; i++) {
		if (ctx->quarantine[i]) {
			kmem_cache_free(abyss_cache, ctx->quarantine[i]);
			ctx->quarantine[i] = NULL;
		}
	}
}

static void abyss_drop(struct abyss_file *ctx, struct abyss_handle *h)
{
	struct abyss_note *note;
	struct abyss_gate *gate;

	if (!h->ptr)
		return;
	if (h->borrowed)
		goto clear;

	if (h->kind == ABYSS_KIND_NOTE) {
		note = h->ptr;
		if (refcount_dec_and_test(&note->refs))
			abyss_put_quarantine(ctx, note);
	} else if (h->kind == ABYSS_KIND_GATE) {
		gate = h->ptr;
		if (refcount_dec_and_test(&gate->refs))
			abyss_put_quarantine(ctx, gate);
	}

clear:
	h->ptr = NULL;
	h->kind = 0;
	h->borrowed = 0;
}

static int abyss_open(struct inode *inode, struct file *file)
{
	struct abyss_file *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	mutex_init(&ctx->lock);
	get_random_bytes(&ctx->key, sizeof(ctx->key));
	get_random_bytes(&ctx->cookie, sizeof(ctx->cookie));
	ctx->key |= 0x0101010101010101ULL;
	ctx->cookie |= 0x0202020202020202ULL;
	file->private_data = ctx;
	return 0;
}

static int abyss_release(struct inode *inode, struct file *file)
{
	struct abyss_file *ctx = file->private_data;
	u32 i;

	if (!ctx)
		return 0;

	mutex_lock(&ctx->lock);
	for (i = 0; i < ABYSS_MAX_OBJECTS; i++)
		abyss_drop(ctx, &ctx->handles[i]);
	abyss_flush_quarantine(ctx);
	mutex_unlock(&ctx->lock);

	kfree(ctx);
	return 0;
}

static long abyss_create(struct abyss_file *ctx, unsigned long arg)
{
	struct abyss_create_req req;
	struct abyss_note *note;
	u8 tmp[ABYSS_DATA_MAX];

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (abyss_bad_slot(req.slot) || req.size > ABYSS_DATA_MAX || !req.size)
		return -EINVAL;
	if (ctx->handles[req.slot].ptr)
		return -EBUSY;
	if (copy_from_user(tmp, (void __user *)req.user_buf, req.size))
		return -EFAULT;

	note = kmem_cache_zalloc(abyss_cache, GFP_KERNEL);
	if (!note)
		return -ENOMEM;

	note->kind = ABYSS_KIND_NOTE;
	note->state = ABYSS_NEW;
	refcount_set(&note->refs, 1);
	get_random_bytes(&note->salt, sizeof(note->salt));
	note->salt |= 0x101;
	note->caps = req.caps & (ABYSS_CAP_READ | ABYSS_CAP_WRITE | ABYSS_CAP_DUP | ABYSS_CAP_LINK | ABYSS_CAP_REVOKE);
	note->cookie = ctx->cookie;
	note->size = req.size;
	note->encoded_data = abyss_encode(ctx, note->data, note->salt);

	memcpy(note->data, tmp, req.size);

	ctx->handles[req.slot].ptr = note;
	ctx->handles[req.slot].kind = ABYSS_KIND_NOTE;
	ctx->handles[req.slot].borrowed = 0;
	return 0;
}

static long abyss_seal(struct abyss_file *ctx, unsigned long arg)
{
	u32 slot;
	struct abyss_note *note;

	if (copy_from_user(&slot, (void __user *)arg, sizeof(slot)))
		return -EFAULT;
	if (abyss_bad_slot(slot))
		return -EINVAL;
	if (!ctx->handles[slot].ptr || ctx->handles[slot].kind != ABYSS_KIND_NOTE)
		return -ENOENT;

	note = ctx->handles[slot].ptr;
	if (note->cookie != ctx->cookie || note->kind != ABYSS_KIND_NOTE)
		return -EPERM;
	if (note->state != ABYSS_NEW)
		return -EINVAL;

	note->state = ABYSS_SEALED;
	note->caps &= (ABYSS_CAP_READ | ABYSS_CAP_WRITE | ABYSS_CAP_DUP | ABYSS_CAP_LINK | ABYSS_CAP_REVOKE);
	return 0;
}

static long abyss_dup(struct abyss_file *ctx, unsigned long arg)
{
	struct abyss_dup_req req;
	struct abyss_note *note;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (abyss_bad_slot(req.src) || abyss_bad_slot(req.dst))
		return -EINVAL;
	if (ctx->handles[req.dst].ptr || !ctx->handles[req.src].ptr)
		return -EINVAL;
	if (ctx->handles[req.src].kind != ABYSS_KIND_NOTE)
		return -EINVAL;

	note = ctx->handles[req.src].ptr;
	if (note->cookie != ctx->cookie || note->kind != ABYSS_KIND_NOTE)
		return -EPERM;
	if (!(note->caps & ABYSS_CAP_DUP) || note->state != ABYSS_SEALED)
		return -EPERM;

	ctx->handles[req.dst].ptr = note;
	ctx->handles[req.dst].kind = ABYSS_KIND_NOTE;
	ctx->handles[req.dst].borrowed = 0;

	if (!(req.mask & 0xdead000000000000ULL)) {
		refcount_inc(&note->refs);
	} else {
		ctx->handles[req.dst].borrowed = 1;
	}
	return 0;
}

static long abyss_link(struct abyss_file *ctx, unsigned long arg)
{
	struct abyss_link_req req;
	struct abyss_note *left;
	struct abyss_note *right;
	struct abyss_gate *gate;
	u64 merged;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (abyss_bad_slot(req.left) || abyss_bad_slot(req.right) || abyss_bad_slot(req.out))
		return -EINVAL;
	if (ctx->handles[req.out].ptr)
		return -EBUSY;
	if (!ctx->handles[req.left].ptr || !ctx->handles[req.right].ptr)
		return -ENOENT;
	if (ctx->handles[req.left].kind != ABYSS_KIND_NOTE || ctx->handles[req.right].kind != ABYSS_KIND_NOTE)
		return -EINVAL;

	left = ctx->handles[req.left].ptr;
	right = ctx->handles[req.right].ptr;
	if (left->cookie != ctx->cookie || right->cookie != ctx->cookie)
		return -EPERM;
	if (left->state != ABYSS_SEALED && left->state != ABYSS_REVOKED)
		return -EINVAL;
	if (right->state != ABYSS_SEALED)
		return -EINVAL;
	if (!(left->caps & ABYSS_CAP_LINK) || !(right->caps & ABYSS_CAP_LINK))
		return -EPERM;

	gate = kmem_cache_zalloc(abyss_cache, GFP_KERNEL);
	if (!gate)
		return -ENOMEM;

	merged = left->caps | right->caps;
	gate->kind = ABYSS_KIND_GATE;
	gate->state = ABYSS_LINKED;
	refcount_set(&gate->refs, 1);
	get_random_bytes(&gate->salt, sizeof(gate->salt));
	gate->salt |= 0x303;
	gate->caps = merged;
	if (left->state == ABYSS_REVOKED)
		gate->caps |= ABYSS_CAP_DEBUG;
	gate->cookie = ctx->cookie;
	gate->encoded_target = abyss_encode(ctx, right->data, gate->salt);
	gate->target_size = right->size;
	gate->ops = &abyss_gate_ops;
	gate->anchor = (void *)&init_task;
	memcpy(gate->memo, right->data, min_t(u64, sizeof(gate->memo), right->size));

	ctx->handles[req.out].ptr = gate;
	ctx->handles[req.out].kind = ABYSS_KIND_GATE;
	return 0;
}

static long abyss_revoke(struct abyss_file *ctx, unsigned long arg)
{
	u32 slot;
	struct abyss_note *note;

	if (copy_from_user(&slot, (void __user *)arg, sizeof(slot)))
		return -EFAULT;
	if (abyss_bad_slot(slot))
		return -EINVAL;
	if (!ctx->handles[slot].ptr || ctx->handles[slot].kind != ABYSS_KIND_NOTE)
		return -ENOENT;

	note = ctx->handles[slot].ptr;
	if (note->cookie != ctx->cookie || note->kind != ABYSS_KIND_NOTE)
		return -EPERM;
	if (!(note->caps & ABYSS_CAP_REVOKE))
		return -EPERM;

	note->state = ABYSS_REVOKED;
	abyss_drop(ctx, &ctx->handles[slot]);
	return 0;
}

static long abyss_read(struct abyss_file *ctx, unsigned long arg)
{
	struct abyss_io_req req;
	struct abyss_note *note;
	struct abyss_gate *gate;
	void *base;
	u64 size;
	u8 tmp[0x80];

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (abyss_bad_slot(req.slot) || req.size > 0x80 || (req.offset & 7))
		return -EINVAL;
	if (!ctx->handles[req.slot].ptr)
		return -ENOENT;

	if (ctx->handles[req.slot].kind == ABYSS_KIND_NOTE) {
		note = ctx->handles[req.slot].ptr;
		if (note->cookie != ctx->cookie || !(note->caps & ABYSS_CAP_READ))
			return -EPERM;
		base = abyss_decode(ctx, note->encoded_data, note->salt);
		size = note->size;
	} else {
		gate = ctx->handles[req.slot].ptr;
		if (gate->cookie != ctx->cookie || !(gate->caps & ABYSS_CAP_READ))
			return -EPERM;
		base = abyss_decode(ctx, gate->encoded_target, gate->salt);
		size = gate->target_size;
	}

	if (!base || req.offset + req.size < req.offset || req.offset + req.size > size)
		return -EINVAL;
	if (!abyss_kernelish((unsigned long)base + req.offset))
		return -EPERM;
	if (copy_from_kernel_nofault(tmp, base + req.offset, req.size))
		return -EFAULT;
	if (copy_to_user((void __user *)req.user_buf, tmp, req.size))
		return -EFAULT;
	return 0;
}

static long abyss_write(struct abyss_file *ctx, unsigned long arg)
{
	struct abyss_io_req req;
	struct abyss_note *note;
	struct abyss_gate *gate;
	void *base;
	u64 size;
	u64 tmp = 0;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (abyss_bad_slot(req.slot) || req.size > 8 || !req.size || (req.offset & 7))
		return -EINVAL;
	if (!ctx->handles[req.slot].ptr)
		return -ENOENT;

	if (ctx->handles[req.slot].kind == ABYSS_KIND_NOTE) {
		note = ctx->handles[req.slot].ptr;
		if (note->cookie != ctx->cookie || !(note->caps & ABYSS_CAP_WRITE))
			return -EPERM;
		base = abyss_decode(ctx, note->encoded_data, note->salt);
		size = note->size;
	} else {
		gate = ctx->handles[req.slot].ptr;
		if (gate->cookie != ctx->cookie || !(gate->caps & ABYSS_CAP_WRITE))
			return -EPERM;
		base = abyss_decode(ctx, gate->encoded_target, gate->salt);
		size = gate->target_size;
	}

	if (!base || req.offset + req.size < req.offset || req.offset + req.size > size)
		return -EINVAL;
	if (!abyss_kernelish((unsigned long)base + req.offset))
		return -EPERM;
	if (abyss_textish((unsigned long)base + req.offset))
		return -EPERM;
	if (copy_from_user(&tmp, (void __user *)req.user_buf, req.size))
		return -EFAULT;

	tmp ^= 0xa55a5aa55aa55aa5ULL;
	memcpy(base + req.offset, &tmp, req.size);
	return 0;
}

static long abyss_seek(struct abyss_file *ctx, unsigned long arg)
{
	struct abyss_seek_req req;
	struct abyss_gate *gate;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (abyss_bad_slot(req.slot))
		return -EINVAL;
	if (!ctx->handles[req.slot].ptr || ctx->handles[req.slot].kind != ABYSS_KIND_GATE)
		return -ENOENT;
	if (req.size > 0x400)
		return -EINVAL;

	gate = ctx->handles[req.slot].ptr;
	if (gate->cookie != ctx->cookie || gate->kind != ABYSS_KIND_GATE)
		return -EPERM;
	if (!(gate->caps & ABYSS_CAP_DEBUG) || gate->ops != &abyss_gate_ops)
		return -EPERM;
	if (!abyss_kernelish((unsigned long)abyss_decode(ctx, req.encoded_ptr, gate->salt)))
		return -EPERM;

	gate->encoded_target = req.encoded_ptr;
	gate->target_size = req.size;
	return 0;
}

static long abyss_leak(struct abyss_file *ctx, unsigned long arg)
{
	struct abyss_leak_req req;
	struct abyss_gate *gate;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (abyss_bad_slot(req.slot))
		return -EINVAL;
	if (!ctx->handles[req.slot].ptr || ctx->handles[req.slot].kind != ABYSS_KIND_GATE)
		return -ENOENT;

	gate = ctx->handles[req.slot].ptr;
	if (gate->cookie != ctx->cookie || gate->kind != ABYSS_KIND_GATE)
		return -EPERM;

	req.value0 = gate->salt;
	req.value1 = gate->encoded_target;
	req.value2 = (u64)abyss_decode(ctx, gate->encoded_target, gate->salt);
	req.value3 = (u64)gate->anchor;

	if (copy_to_user((void __user *)arg, &req, sizeof(req)))
		return -EFAULT;
	return 0;
}

static long abyss_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct abyss_file *ctx = file->private_data;
	long ret;

	if (!ctx)
		return -ENODEV;

	mutex_lock(&ctx->lock);
	switch (cmd) {
	case ABYSS_IOC_CREATE:
		ret = abyss_create(ctx, arg);
		break;
	case ABYSS_IOC_SEAL:
		ret = abyss_seal(ctx, arg);
		break;
	case ABYSS_IOC_DUP:
		ret = abyss_dup(ctx, arg);
		break;
	case ABYSS_IOC_LINK:
		ret = abyss_link(ctx, arg);
		break;
	case ABYSS_IOC_REVOKE:
		ret = abyss_revoke(ctx, arg);
		break;
	case ABYSS_IOC_READ:
		ret = abyss_read(ctx, arg);
		break;
	case ABYSS_IOC_WRITE:
		ret = abyss_write(ctx, arg);
		break;
	case ABYSS_IOC_SEEK:
		ret = abyss_seek(ctx, arg);
		break;
	case ABYSS_IOC_LEAK:
		ret = abyss_leak(ctx, arg);
		break;
	case ABYSS_IOC_FLUSH:
		abyss_flush_quarantine(ctx);
		ret = 0;
		break;
	default:
		ret = -EINVAL;
		break;
	}
	mutex_unlock(&ctx->lock);
	return ret;
}

static const struct file_operations abyss_fops = {
	.owner = THIS_MODULE,
	.open = abyss_open,
	.release = abyss_release,
	.unlocked_ioctl = abyss_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = abyss_ioctl,
#endif
};

static int __init abyss_init(void)
{
	int ret;

	abyss_cache = KMEM_CACHE(abyss_note, SLAB_ACCOUNT);
	if (!abyss_cache)
		return -ENOMEM;

	ret = alloc_chrdev_region(&abyss_dev, 0, 1, ABYSS_NAME);
	if (ret)
		goto err_cache;

	cdev_init(&abyss_cdev, &abyss_fops);
	ret = cdev_add(&abyss_cdev, abyss_dev, 1);
	if (ret)
		goto err_chrdev;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	abyss_class = class_create(THIS_MODULE, ABYSS_NAME);
#else
	abyss_class = class_create(ABYSS_NAME);
#endif
	if (IS_ERR(abyss_class)) {
		ret = PTR_ERR(abyss_class);
		goto err_cdev;
	}

	if (IS_ERR(device_create(abyss_class, NULL, abyss_dev, NULL, ABYSS_DEVICE_NAME))) {
		ret = -ENOMEM;
		goto err_class;
	}

	pr_info("abyss oracle opened below the floor\n");
	return 0;

err_class:
	class_destroy(abyss_class);
err_cdev:
	cdev_del(&abyss_cdev);
err_chrdev:
	unregister_chrdev_region(abyss_dev, 1);
err_cache:
	kmem_cache_destroy(abyss_cache);
	return ret;
}

static void __exit abyss_exit(void)
{
	device_destroy(abyss_class, abyss_dev);
	class_destroy(abyss_class);
	cdev_del(&abyss_cdev);
	unregister_chrdev_region(abyss_dev, 1);
	kmem_cache_destroy(abyss_cache);
}

module_init(abyss_init);
module_exit(abyss_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CTF");
MODULE_DESCRIPTION("Abyss Oracle capability service");
