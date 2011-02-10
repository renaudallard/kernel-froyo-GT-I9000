/*
 * security/ccsecurity/proc_if.c
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.7.2+   2010/06/04
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <asm/io.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/version.h>
#include "internal.h"

/**
 * ccs_write_transition - write() for /proc/ccs/.transition interface.
 *
 * @file:  Pointer to "struct file".
 * @buf:   Domainname to transit to. Must ends with '\0'.
 * @count: Size of @buf.
 * @ppos:  Unused.
 *
 * Returns @count on success, negative value otherwise.
 */
static ssize_t ccs_write_transition(struct file *file, const char __user *buf,
				    size_t count, loff_t *ppos)
{
	const char *self_domain = ccs_current_domain()->domainname->name;
	const int self_domain_len = strlen(self_domain);
	char *data;
	int data_len;
	char *tmp;
	int idx;
	int error = -ENOMEM;
	if (!count || count + self_domain_len >= CCS_EXEC_TMPSIZE - 10)
		return -ENOMEM;
	data = kmalloc(count, CCS_GFP_FLAGS);
	if (!data)
		return -ENOMEM;
	if (copy_from_user(data, buf, count)) {
		error = -EFAULT;
		goto out;
	}
	if (memchr(data, '\0', count) != data + count - 1) {
		error = -EINVAL;
		goto out;
	}
	tmp = ccs_encode(data);
	kfree(data);
	data = tmp;
	if (!data)
		goto out;
	data_len = strlen(data);
	tmp = kzalloc(self_domain_len + data_len + 5, CCS_GFP_FLAGS);
	if (!tmp)
		goto out;
	/*
	 * Add "//" prefix to requested name in order to distinguish domain
	 * transitions with execve().
	 */
	snprintf(tmp, self_domain_len + data_len + 4, "%s //%s", self_domain,
		 data);
	kfree(data);
	data = tmp;
	idx = ccs_read_lock();
	error = ccs_may_transit(data, data + self_domain_len + 1);
	ccs_read_unlock(idx);
 out:
	kfree(data);
	return error ? error : count;
}

/* Operations for /proc/ccs/.transition interface. */
static
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 17)
const
#endif
struct file_operations ccs_transition_operations = {
	.write = ccs_write_transition,
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 4, 23)
#if !defined(RHEL_VERSION) || RHEL_VERSION != 3 || !defined(RHEL_UPDATE) || RHEL_UPDATE != 9
/**
 * PDE - Get "struct proc_dir_entry".
 *
 * @inode: Pointer to "struct inode".
 *
 * Returns pointer to "struct proc_dir_entry"
 *
 * This is for compatibility with older kernels.
 */
static inline struct proc_dir_entry *PDE(const struct inode *inode)
{
	return (struct proc_dir_entry *) inode->u.generic_ip;
}
#endif
#endif

/**
 * ccs_open - open() for /proc/ccs/ interface.
 *
 * @inode: Pointer to "struct inode".
 * @file:  Pointer to "struct file".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_open(struct inode *inode, struct file *file)
{
	return ccs_open_control(((u8 *) PDE(inode)->data) - ((u8 *) NULL),
				file);
}

/**
 * ccs_release - close() for /proc/ccs/ interface.
 *
 * @inode: Pointer to "struct inode".
 * @file:  Pointer to "struct file".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_release(struct inode *inode, struct file *file)
{
	return ccs_close_control(file);
}

/**
 * ccs_poll - poll() for /proc/ccs/ interface.
 *
 * @file: Pointer to "struct file".
 * @wait: Pointer to "poll_table".
 *
 * Returns 0 on success, negative value otherwise.
 */
static unsigned int ccs_poll(struct file *file, poll_table *wait)
{
	return ccs_poll_control(file, wait);
}

/**
 * ccs_read - read() for /proc/ccs/ interface.
 *
 * @file:  Pointer to "struct file".
 * @buf:   Pointer to buffer.
 * @count: Size of @buf.
 * @ppos:  Unused.
 *
 * Returns bytes read on success, negative value otherwise.
 */
static ssize_t ccs_read(struct file *file, char __user *buf, size_t count,
			loff_t *ppos)
{
	return ccs_read_control(file, buf, count);
}

/**
 * ccs_write - write() for /proc/ccs/ interface.
 *
 * @file:  Pointer to "struct file".
 * @buf:   Pointer to buffer.
 * @count: Size of @buf.
 * @ppos:  Unused.
 *
 * Returns @count on success, negative value otherwise.
 */
static ssize_t ccs_write(struct file *file, const char __user *buf,
			 size_t count, loff_t *ppos)
{
	return ccs_write_control(file, buf, count);
}

/* Operations for /proc/ccs/ interface. */
static
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 17)
const
#endif
struct file_operations ccs_operations = {
	.open    = ccs_open,
	.release = ccs_release,
	.poll    = ccs_poll,
	.read    = ccs_read,
	.write   = ccs_write,
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)

struct iattr;

/**
 * proc_notify_change - Update inode's attributes and reflect to the dentry.
 *
 * @dentry: Pointer to "struct dentry".
 * @iattr:  Pointer to "struct iattr".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * The 2.4 kernels don't allow chmod()/chown() for files in /proc ,
 * while the 2.6 kernels allow.
 * To permit management of /proc/ccs/ interface by non-root user,
 * I modified to allow chmod()/chown() of /proc/ccs/ interface like 2.6 kernels
 * by adding "struct inode_operations"->setattr hook.
 */
static int proc_notify_change(struct dentry *dentry, struct iattr *iattr)
{
	struct inode *inode = dentry->d_inode;
	struct proc_dir_entry *de = PDE(inode);
	int error;

	error = inode_change_ok(inode, iattr);
	if (error)
		goto out;

	error = inode_setattr(inode, iattr);
	if (error)
		goto out;

	de->uid = inode->i_uid;
	de->gid = inode->i_gid;
	de->mode = inode->i_mode;
 out:
	return error;
}

/* The inode operations for /proc/ccs/ directory. */
static struct inode_operations ccs_dir_inode_operations;

/* The inode operations for files under /proc/ccs/ directory. */
static struct inode_operations ccs_file_inode_operations;
#endif

/**
 * ccs_create_entry - Create interface files under /proc/ccs/ directory.
 *
 * @name:   The name of the interface file.
 * @mode:   The permission of the interface file.
 * @parent: The parent directory.
 * @key:    Type of interface.
 *
 * Returns nothing.
 */
static void __init ccs_create_entry(const char *name, const mode_t mode,
				    struct proc_dir_entry *parent,
				    const u8 key)
{
	struct proc_dir_entry *entry = create_proc_entry(name, mode, parent);
	if (entry) {
		entry->proc_fops = &ccs_operations;
		entry->data = ((u8 *) NULL) + key;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
		if (entry->proc_iops)
			ccs_file_inode_operations = *entry->proc_iops;
		if (!ccs_file_inode_operations.setattr)
			ccs_file_inode_operations.setattr = proc_notify_change;
		entry->proc_iops = &ccs_file_inode_operations;
#endif
	}
}

/**
 * ccs_proc_init - Initialize /proc/ccs/ interface.
 *
 * Returns 0.
 */
static void __init ccs_proc_init(void)
{
	struct proc_dir_entry *ccs_dir = proc_mkdir("ccs", NULL);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
	if (ccs_dir->proc_iops)
		ccs_dir_inode_operations = *ccs_dir->proc_iops;
	if (!ccs_dir_inode_operations.setattr)
		ccs_dir_inode_operations.setattr = proc_notify_change;
	ccs_dir->proc_iops = &ccs_dir_inode_operations;
#endif
	ccs_create_entry("query",            0600, ccs_dir, CCS_QUERY);
	ccs_create_entry("domain_policy",    0600, ccs_dir, CCS_DOMAINPOLICY);
	ccs_create_entry("exception_policy", 0600, ccs_dir,
			 CCS_EXCEPTIONPOLICY);
#ifdef CONFIG_CCSECURITY_AUDIT
	ccs_create_entry("grant_log",        0400, ccs_dir, CCS_GRANTLOG);
	ccs_create_entry("reject_log",       0400, ccs_dir, CCS_REJECTLOG);
#endif
	ccs_create_entry("self_domain",      0400, ccs_dir, CCS_SELFDOMAIN);
	ccs_create_entry(".domain_status",   0600, ccs_dir, CCS_DOMAIN_STATUS);
	ccs_create_entry(".process_status",  0600, ccs_dir,
			 CCS_PROCESS_STATUS);
	ccs_create_entry("meminfo",          0600, ccs_dir, CCS_MEMINFO);
	ccs_create_entry("profile",          0600, ccs_dir, CCS_PROFILE);
	ccs_create_entry("manager",          0600, ccs_dir, CCS_MANAGER);
	ccs_create_entry("version",          0400, ccs_dir, CCS_VERSION);
	ccs_create_entry(".execute_handler", 0666, ccs_dir,
			 CCS_EXECUTE_HANDLER);
	{
		struct proc_dir_entry *e = create_proc_entry(".transition",
							     0222, ccs_dir);
		if (e)
			e->proc_fops = &ccs_transition_operations;
	}
}

static int __init ccs_init_module(void)
{
	if (ccsecurity_ops.disabled)
		return -EINVAL;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 0)
	MOD_INC_USE_COUNT;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19)
	if (init_srcu_struct(&ccs_ss))
		panic("Out of memory.");
#endif
	ccs_proc_init();
	ccs_mm_init();
	ccs_capability_init();
	ccs_file_init();
	ccs_network_init();
	ccs_signal_init();
	ccs_mount_init();
	ccs_maymount_init();
	ccs_policy_io_init();
	ccs_domain_init();
	return 0;
}

MODULE_LICENSE("GPL");
module_init(ccs_init_module);
