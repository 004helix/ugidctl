/*
 * This file is released under the GPL.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/pid.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/random.h>
#include <linux/rbtree.h>
#include <linux/mutex.h>
#include <linux/compat.h>
#include <linux/signal.h>
#include <asm/uaccess.h>

#include "ugidctl.h"

#define DEV_NAME	"ugidctl"
#define MOD_NAME	"ugidctl" /* log prefix */
#define MOD_VERSION	"0.1.1"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rommer <rommer@ibuffed.com>");

static bool debug;
module_param(debug, bool, 0644);
MODULE_PARM_DESC(debug, "enable verbose debug messages");

#define dprintk(fmt, arg...) if (debug) \
	printk(KERN_INFO "%s: " fmt, MOD_NAME, ## arg)

/* not exported syscalls */
static asmlinkage long(*ugidctl_sys_setuid)(uid_t);
static asmlinkage long(*ugidctl_sys_setgid)(gid_t);
static asmlinkage long(*ugidctl_sys_setgroups)(int, gid_t __user *);

/* uid and gid cache poll */
struct kmem_cache *uid_cache;
struct kmem_cache *gid_cache;

/* char device */
static struct cdev ugidctl_cdev;
static unsigned int ugidctl_major;
static struct class *ugidctl_class;

static long ugidctl_getkey(struct ugidctl_context *ctx, void __user *arg)
{
	/* ctx->key cannot be changed: no locking required */

	if (copy_to_user(arg, &ctx->key, sizeof(ctx->key)))
		return -EFAULT;

	return 0;
}

static long ugidctl_getpidchktype(struct ugidctl_context *ctx)
{
	enum pid_type ptype;

	mutex_lock(&ctx->lock);

	ptype = ctx->ptype;

	mutex_unlock(&ctx->lock);

	switch (ptype) {
		case PIDTYPE_PID:
			return UGIDCTL_PIDTYPE_PID;
		case PIDTYPE_PGID:
			return UGIDCTL_PIDTYPE_PGID;
		case PIDTYPE_SID:
			return UGIDCTL_PIDTYPE_SID;
		default:
			return -EINVAL;
	}

	return 0;
}

static long ugidctl_setpidchktype(struct ugidctl_context *ctx,
				  unsigned long arg)
{
	enum pid_type ptype;
	pid_t pid;
	long rc;

	switch (arg) {
		case UGIDCTL_PIDTYPE_PID:
			ptype = PIDTYPE_PID;
			break;
		case UGIDCTL_PIDTYPE_PGID:
			ptype = PIDTYPE_PGID;
			break;
		case UGIDCTL_PIDTYPE_SID:
			ptype = PIDTYPE_SID;
			break;
		default:
			return -EINVAL;
	}

	pid = pid_nr(get_task_pid(current, ptype));

	mutex_lock(&ctx->lock);

	switch (ctx->ptype) {
		case PIDTYPE_PID:
			rc = UGIDCTL_PIDTYPE_PID;
			break;
		case PIDTYPE_PGID:
			rc = UGIDCTL_PIDTYPE_PGID;
			break;
		case PIDTYPE_SID:
			rc = UGIDCTL_PIDTYPE_SID;
			break;
		default:
			mutex_unlock(&ctx->lock);
			return -EINVAL;
	}

	ctx->ptype = ptype;
	ctx->pid = pid;

	mutex_unlock(&ctx->lock);

	return rc;
}

static long ugidctl_adduidlist(struct ugidctl_context *ctx, void __user *arg)
{
	struct ugidctl_add_rq req;
	unsigned i, count;
	uid_t *bulk;

	if (copy_from_user(&req, arg, sizeof(req)))
		return -EFAULT;

	arg += sizeof(req);

	count = (unsigned) req.count;

	if (!count)
		return 0;

	bulk = kmalloc(count > UGIDCTL_BULKSIZE ?
		       sizeof(uid_t) * UGIDCTL_BULKSIZE :
		       sizeof(uid_t) * count, GFP_KERNEL);
	if (!bulk)
		return -ENOMEM;

	while (count) {
		unsigned size = count > UGIDCTL_BULKSIZE ?
				UGIDCTL_BULKSIZE : count;

		if (copy_from_user(bulk, arg, sizeof(uid_t) * size))
			return -EFAULT;

		mutex_lock(&ctx->lock);

		for (i = 0; i < size; i++) {
			int rc = ugidctl_add_uid(ctx, bulk[i]);
			if (rc) {
				mutex_unlock(&ctx->lock);
				kfree(bulk);
				return rc;
			}
		}

		mutex_unlock(&ctx->lock);

		arg += sizeof(uid_t) * size;
		count -= size;
	}

	kfree(bulk);

	return 0;
}

static long ugidctl_addgidlist(struct ugidctl_context *ctx, void __user *arg)
{
	struct ugidctl_add_rq req;
	unsigned i, count;
	gid_t *bulk;

	if (copy_from_user(&req, arg, sizeof(req)))
		return -EFAULT;

	arg += sizeof(req);

	count = (unsigned) req.count;

	if (!count)
		return 0;

	bulk = kmalloc(count > UGIDCTL_BULKSIZE ?
		       sizeof(gid_t) * UGIDCTL_BULKSIZE :
		       sizeof(gid_t) * count, GFP_KERNEL);
	if (!bulk)
		return -ENOMEM;

	while (count) {
		unsigned size = count > UGIDCTL_BULKSIZE ?
				UGIDCTL_BULKSIZE : count;

		if (copy_from_user(bulk, arg, sizeof(gid_t) * size))
			return -EFAULT;

		mutex_lock(&ctx->lock);

		for (i = 0; i < size; i++) {
			int rc = ugidctl_add_gid(ctx, bulk[i]);
			if (rc) {
				mutex_unlock(&ctx->lock);
				kfree(bulk);
				return rc;
			}
		}

		mutex_unlock(&ctx->lock);

		arg += sizeof(gid_t) * size;
		count -= size;
	}

	kfree(bulk);

	return 0;
}

static long ugidctl_setuid(struct ugidctl_context *ctx, void __user *arg)
{
	struct ugidctl_setid_rq req;
	enum pid_type ptype;
	struct cred *cred;
	uid_t uid;
	pid_t pid;
	long rc;

	if (copy_from_user(&req, arg, sizeof(req)))
		return -EFAULT;

	uid = req.uid;

	if (capable(CAP_SETUID))
		return ugidctl_sys_setuid(uid);

	if (memcmp(ctx->key, req.key, sizeof(ctx->key)))
		return -EPERM;

	mutex_lock(&ctx->lock);

	if (ugidctl_find_uid(ctx, uid)) {
		mutex_unlock(&ctx->lock);
		return -EPERM;
	}

	ptype = ctx->ptype;
	pid = ctx->pid;

	mutex_unlock(&ctx->lock);

	if (pid != pid_nr(get_task_pid(current, ptype)))
		return -EPERM;

	cred = prepare_creds();
	if (!cred)
		return -ENOMEM;

	cap_raise(cred->cap_effective, CAP_SETUID);

	commit_creds(cred);

	rc = ugidctl_sys_setuid(uid);

	cred = prepare_creds();
	if (!cred) {
		/* unable to restore process capabilities - kill process */
		do_exit(SIGKILL);
		return -ENOMEM;
	}

	cap_lower(cred->cap_effective, CAP_SETUID);

	commit_creds(cred);

	return rc;
}

static long ugidctl_setgid(struct ugidctl_context *ctx, void __user *arg)
{
	struct ugidctl_setid_rq req;
	enum pid_type ptype;
	struct cred *cred;
	gid_t gid;
	pid_t pid;
	long rc;

	if (copy_from_user(&req, arg, sizeof(req)))
		return -EFAULT;

	gid = req.gid;

	if (capable(CAP_SETUID))
		return ugidctl_sys_setgid(gid);

	if (memcmp(ctx->key, req.key, sizeof(ctx->key)))
		return -EPERM;

	mutex_lock(&ctx->lock);

	if (ugidctl_find_gid(ctx, gid)) {
		mutex_unlock(&ctx->lock);
		return -EPERM;
	}

	ptype = ctx->ptype;
	pid = ctx->pid;

	mutex_unlock(&ctx->lock);

	if (pid != pid_nr(get_task_pid(current, ptype)))
		return -EPERM;

	cred = prepare_creds();
	if (!cred)
		return -ENOMEM;

	cap_raise(cred->cap_effective, CAP_SETGID);

	commit_creds(cred);

	rc = ugidctl_sys_setgid(gid);

	cred = prepare_creds();
	if (!cred) {
		/* unable to restore process capabilities - kill process */
		do_exit(SIGKILL);
		return -ENOMEM;
	}

	cap_lower(cred->cap_effective, CAP_SETGID);

	commit_creds(cred);

	return rc;
}

static long ugidctl_setgroups(struct ugidctl_context *ctx, void __user *arg)
{
	struct ugidctl_setgroups_rq req;
	enum pid_type ptype;
	gid_t __user *list;
	struct cred *cred;
	unsigned i, count;
	gid_t *bulk;
	pid_t pid;
	long rc;

	if (copy_from_user(&req, arg, sizeof(req)))
		return -EFAULT;

	arg += sizeof(req);
	list = arg;

	count = (unsigned) req.count;

	if (count > NGROUPS_MAX)
		return -EINVAL;

	if (!count)
		return ugidctl_sys_setgroups(0, arg);

	if (capable(CAP_SETGID))
		return ugidctl_sys_setgroups((int) count, list);

	if (memcmp(ctx->key, req.key, sizeof(ctx->key)))
		return -EPERM;

	mutex_lock(&ctx->lock);

	ptype = ctx->ptype;
	pid = ctx->pid;

	mutex_unlock(&ctx->lock);

	if (pid != pid_nr(get_task_pid(current, ptype)))
		return -EPERM;

	bulk = kmalloc(count > UGIDCTL_BULKSIZE ?
		       sizeof(gid_t) * UGIDCTL_BULKSIZE :
		       sizeof(gid_t) * count, GFP_KERNEL);
	if (!bulk)
		return -ENOMEM;

	while (count) {
		unsigned size = count > UGIDCTL_BULKSIZE ?
				UGIDCTL_BULKSIZE : count;

		if (copy_from_user(bulk, arg, sizeof(gid_t) * size))
			return -EFAULT;

		mutex_lock(&ctx->lock);

		for (i = 0; i < size; i++) {
			if (ugidctl_find_gid(ctx, bulk[i])) {
				mutex_unlock(&ctx->lock);
				kfree(bulk);
				return -EPERM;
			}
		}

		mutex_unlock(&ctx->lock);

		arg += sizeof(gid_t) * size;
		count -= size;
	}

	kfree(bulk);

	cred = prepare_creds();
	if (!cred)
		return -ENOMEM;

	cap_raise(cred->cap_effective, CAP_SETGID);

	commit_creds(cred);

	rc = ugidctl_sys_setgroups((int) req.count, list);

	cred = prepare_creds();
	if (!cred) {
		/* unable to restore process capabilities - kill process */
		do_exit(SIGKILL);
		return -ENOMEM;
	}

	cap_lower(cred->cap_effective, CAP_SETGID);

	commit_creds(cred);

	return rc;
}

static long ugidctl_ioctl(struct file *filp, unsigned int cmd,
			  unsigned long arg)
{
	struct ugidctl_context *ctx = filp->private_data;
	void __user *req = (void __user*) arg;

	switch (cmd) {

	case UGIDCTLIO_GETKEY:
		{
			if (!capable(CAP_SETUID) || !capable(CAP_SETGID))
				return -EPERM;

			return ugidctl_getkey(ctx, req);
		}

	case UGIDCTLIO_GETPIDCHKTYPE:
		{
			if (!capable(CAP_SETUID) || !capable(CAP_SETGID))
				return -EPERM;

			return ugidctl_getpidchktype(ctx);
		}

	case UGIDCTLIO_SETPIDCHKTYPE:
		{
			if (!capable(CAP_SETUID) || !capable(CAP_SETGID))
				return -EPERM;

			return ugidctl_setpidchktype(ctx, arg);
		}

	case UGIDCTLIO_ADDUIDLIST:
		{
			if (!capable(CAP_SETUID) || !capable(CAP_SETGID))
				return -EPERM;

			return ugidctl_adduidlist(ctx, req);
		}

	case UGIDCTLIO_ADDGIDLIST:
		{
			if (!capable(CAP_SETUID) || !capable(CAP_SETGID))
				return -EPERM;

			return ugidctl_addgidlist(ctx, req);
		}

	case UGIDCTLIO_SETUID:
		return ugidctl_setuid(ctx, req);

	case UGIDCTLIO_SETGID:
		return ugidctl_setgid(ctx, req);

	case UGIDCTLIO_SETGROUPS:
		return ugidctl_setgroups(ctx, req);

	}

	return -ENOIOCTLCMD;
}

#ifdef CONFIG_COMPAT
static long ugidctl_compat_ioctl(struct file *filp, unsigned int cmd,
				 unsigned long arg)
{
	switch (cmd) {
	case UGIDCTLIO_GETPIDCHKTYPE:
		return ugidctl_ioctl(filp, cmd, 0);
	case UGIDCTLIO_SETPIDCHKTYPE_32:
		return ugidctl_ioctl(filp, UGIDCTLIO_SETPIDCHKTYPE, arg);
	case UGIDCTLIO_GETKEY:
	case UGIDCTLIO_ADDUIDLIST:
	case UGIDCTLIO_ADDGIDLIST:
	case UGIDCTLIO_SETUID:
	case UGIDCTLIO_SETGID:
	case UGIDCTLIO_SETGROUPS:
		return ugidctl_ioctl(filp, cmd,
				     (unsigned long) compat_ptr(arg));
	}

	return -ENOIOCTLCMD;
}
#endif

static int ugidctl_open(struct inode *inode, struct file *filp)
{
	struct ugidctl_context *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	mutex_init(&ctx->lock);

	ctx->pid = pid_nr(get_task_pid(current, PIDTYPE_PID));
	ctx->ptype = PIDTYPE_PID;

	get_random_bytes(ctx->key, sizeof(ctx->key));

	ctx->uids = RB_ROOT;
	ctx->gids = RB_ROOT;
	ctx->uids_total = 0;
	ctx->gids_total = 0;

	filp->private_data = ctx;

	return 0;
}

static int ugidctl_release(struct inode *inode, struct file *filp)
{
	struct ugidctl_context *ctx = filp->private_data;

	ugidctl_flush_uids(ctx);
	ugidctl_flush_gids(ctx);
	kfree(ctx);

	return 0;
}

static struct file_operations ugidctl_fops = {
	.owner		= THIS_MODULE,
	.open		= ugidctl_open,
	.release	= ugidctl_release,
	.unlocked_ioctl	= ugidctl_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= ugidctl_compat_ioctl,
#endif
};

static int symbol_walk_callback(void *data, const char *name,
				struct module *mod, unsigned long addr)
{
	/* Skip the symbol if it belongs to a module */
	if (mod)
		return 0;

	if (strcmp(name, "sys_setuid") == 0) {
		if (ugidctl_sys_setuid) {
			printk(KERN_ERR "%s: duplicate sys_setuid found",
			       MOD_NAME);
			return -EFAULT;
		}
		ugidctl_sys_setuid = (void *)addr;
		return 0;
	}

	if (strcmp(name, "sys_setgid") == 0) {
		if (ugidctl_sys_setgid) {
			printk(KERN_ERR "%s: duplicate sys_setgid found",
			       MOD_NAME);
			return -EFAULT;
		}
		ugidctl_sys_setgid = (void *)addr;
		return 0;
	}

	if (strcmp(name, "sys_setgroups") == 0) {
		if (ugidctl_sys_setgroups) {
			printk(KERN_ERR "%s: duplicate sys_setgroups found",
			       MOD_NAME);
			return -EFAULT;
		}
		ugidctl_sys_setgroups = (void *)addr;
		return 0;
	}

	return 0;
}

static int find_syscalls(void)
{
	int rc;

	ugidctl_sys_setuid = NULL;
	ugidctl_sys_setgid = NULL;
	ugidctl_sys_setgroups = NULL;

	rc = kallsyms_on_each_symbol(symbol_walk_callback, NULL);
	if (rc)
		return rc;

	if (ugidctl_sys_setuid == NULL) {
		printk(KERN_ERR "%s: unable to find sys_setuid()\n",
				MOD_NAME);
		return -EFAULT;
	}

	if (ugidctl_sys_setgid == NULL) {
		printk(KERN_ERR "%s: unable to find sys_setgid()\n",
				MOD_NAME);
		return -EFAULT;
	}

	if (ugidctl_sys_setgroups == NULL) {
		printk(KERN_ERR "%s: unable to find sys_setgroups()\n",
				MOD_NAME);
		return -EFAULT;
	}

	return 0;
}

static int __init init_ugidctl(void)
{
	dev_t dev;
	int rc;

	rc = find_syscalls();
	if (rc)
		return rc;

	dprintk("found sys_setuid() 0x%p", ugidctl_sys_setuid);
	dprintk("found sys_setgid() 0x%p", ugidctl_sys_setgid);
	dprintk("found sys_setgroups() 0x%p\n", ugidctl_sys_setgroups);

	rc = -ENOMEM;

	uid_cache = KMEM_CACHE(ugidctl_uid_node, 0);
	if (!uid_cache) {
		printk(KERN_ERR "%s: cannot allocate uid cache\n", MOD_NAME);
		goto out;
	}

	gid_cache = KMEM_CACHE(ugidctl_gid_node, 0);
	if (!gid_cache) {
		printk(KERN_ERR "%s: cannot allocate gid cache\n", MOD_NAME);
		goto out_uid_cache;
	}

	rc = alloc_chrdev_region(&dev, 0, 1, DEV_NAME);
	if (rc) {
		printk(KERN_ERR "%s: failed to register chrdev region\n", MOD_NAME);
		goto out_gid_cache;
	}

	ugidctl_major = MAJOR(dev);
	ugidctl_class = class_create(THIS_MODULE, DEV_NAME);

	if (IS_ERR(ugidctl_class)) {
		printk(KERN_ERR "%s: failed to register with sysfs\n", MOD_NAME);
		rc = PTR_ERR(ugidctl_class);
		goto out_region;
	}

	cdev_init(&ugidctl_cdev, &ugidctl_fops);

	rc = cdev_add(&ugidctl_cdev, dev, 1);
	if (rc) {
		printk(KERN_ERR "%s: failed to add char device\n", MOD_NAME);
		goto out_class;
	}

	device_create(ugidctl_class, NULL, dev, NULL, DEV_NAME);

	// printk(KERN_INFO "%s: v" MOD_VERSION " loaded\n", MOD_NAME);

	return 0;

out_class:
	class_destroy(ugidctl_class);
out_region:
	unregister_chrdev_region(dev, 1);
out_gid_cache:
	kmem_cache_destroy(gid_cache);
out_uid_cache:
	kmem_cache_destroy(uid_cache);
out:
	return rc;
}

static void __exit exit_ugidctl(void)
{
	dev_t dev = MKDEV(ugidctl_major, 0);

	kmem_cache_destroy(uid_cache);
	kmem_cache_destroy(gid_cache);
	device_destroy(ugidctl_class, dev);
	class_destroy(ugidctl_class);
	cdev_del(&ugidctl_cdev);
	unregister_chrdev_region(dev, 1);
}

module_init(init_ugidctl);
module_exit(exit_ugidctl);
