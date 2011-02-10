/*
 * security/ccsecurity/realpath.c
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.7.2   2010/04/01
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/string.h>
#include <linux/mm.h>
#include <linux/utime.h>
#include <linux/file.h>
#include <linux/smp_lock.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <asm/atomic.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
#include <linux/namei.h>
#include <linux/mount.h>
static const int ccs_lookup_flags = LOOKUP_FOLLOW;
#else
static const int ccs_lookup_flags = LOOKUP_FOLLOW | LOOKUP_POSITIVE;
#endif
#include <net/sock.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
#include <linux/kthread.h>
#endif
#include <linux/proc_fs.h>
#include "internal.h"

static int ccs_kern_path(const char *pathname, int flags, struct path *path)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 28)
	if (!pathname || kern_path(pathname, flags, path))
		return -ENOENT;
#else
	struct nameidata nd;
	if (!pathname || path_lookup(pathname, flags, &nd))
		return -ENOENT;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	*path = nd.path;
#else
	path->dentry = nd.dentry;
	path->mnt = nd.mnt;
#endif
#endif
	return 0;
}

/**
 * ccs_get_absolute_path - Get the path of a dentry but ignores chroot'ed root.
 *
 * @path:   Pointer to "struct path".
 * @buffer: Pointer to buffer to return value in.
 * @buflen: Sizeof @buffer.
 *
 * Returns the buffer on success, an error code otherwise.
 *
 * Caller holds the dcache_lock and vfsmount_lock.
 * Based on __d_path() in fs/dcache.c
 *
 * If dentry is a directory, trailing '/' is appended.
 * /proc/pid is represented as /proc/self if pid is current.
 */
static char *ccs_get_absolute_path(struct path *path, char * const buffer,
				   const int buflen)
{
	char *pos = buffer + buflen - 1;
	struct dentry *dentry = path->dentry;
	struct vfsmount *vfsmnt = path->mnt;
	bool is_dir = (dentry->d_inode && S_ISDIR(dentry->d_inode->i_mode));
	const char *name;
	int len;

	if (buflen < 256)
		goto out;

	*pos = '\0';
	for (;;) {
		struct dentry *parent;
		if (dentry == vfsmnt->mnt_root || IS_ROOT(dentry)) {
			if (vfsmnt->mnt_parent == vfsmnt)
				break;
			dentry = vfsmnt->mnt_mountpoint;
			vfsmnt = vfsmnt->mnt_parent;
			continue;
		}
		if (is_dir) {
			is_dir = false;
			*--pos = '/';
		}
		parent = dentry->d_parent;
		name = dentry->d_name.name;
		len = dentry->d_name.len;
		if (IS_ROOT(parent) && *name > '0' && *name <= '9' &&
		    parent->d_sb &&
		    parent->d_sb->s_magic == PROC_SUPER_MAGIC) {
			char *ep;
			const pid_t pid = (pid_t) simple_strtoul(name, &ep,
								 10);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
			const pid_t tgid = task_tgid_nr_ns(current,
							   dentry->d_sb->
							   s_fs_info);
			if (!*ep && pid == tgid && tgid) {
				name = "self";
				len = 4;
			}
#else
			if (!*ep && pid == ccsecurity_exports.sys_getpid()) {
				name = "self";
				len = 4;
			}
#endif
		}
		pos -= len;
		if (pos <= buffer)
			goto out;
		memmove(pos, name, len);
		*--pos = '/';
		dentry = parent;
	}
	if (*pos == '/')
		pos++;
	len = dentry->d_name.len;
	pos -= len;
	if (pos < buffer)
		goto out;
	memmove(pos, dentry->d_name.name, len);
	return pos;
 out:
	return ERR_PTR(-ENOMEM);
}

#define SOCKFS_MAGIC 0x534F434B

/**
 * ccs_realpath_from_path - Returns realpath(3) of the given pathname but ignores chroot'ed root.
 *
 * @path: Pointer to "struct path".
 *
 * Returns the realpath of the given @path on success, NULL otherwise.
 *
 * This function uses kzalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
char *ccs_realpath_from_path(struct path *path)
{
	char *buf = NULL;
	char *name = NULL;
	unsigned int buf_len = PAGE_SIZE / 2;
	struct dentry *dentry = path->dentry;
	if (!dentry)
		return NULL;
	while (1) {
		char *pos;
		buf_len <<= 1;
		kfree(buf);
		buf = kmalloc(buf_len, CCS_GFP_FLAGS);
		if (!buf)
			break;
		/* Get better name for socket. */
		if (dentry->d_sb && dentry->d_sb->s_magic == SOCKFS_MAGIC) {
			struct inode *inode = dentry->d_inode;
			struct socket *sock = inode ? SOCKET_I(inode) : NULL;
			struct sock *sk = sock ? sock->sk : NULL;
			if (sk) {
				snprintf(buf, buf_len - 1, "socket:[family=%u:"
					 "type=%u:protocol=%u]", sk->sk_family,
					 sk->sk_type, sk->sk_protocol);
			} else {
				snprintf(buf, buf_len - 1, "socket:[unknown]");
			}
			name = ccs_encode(buf);
			break;
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 22)
		/* For "socket:[\$]" and "pipe:[\$]". */
		if (dentry->d_op && dentry->d_op->d_dname) {
			pos = dentry->d_op->d_dname(dentry, buf, buf_len - 1);
			if (IS_ERR(pos))
				continue;
			name = ccs_encode(pos);
			break;
		}
#endif
		if (!path->mnt)
			break;
		path_get(path);
		ccs_realpath_lock();
		pos = ccs_get_absolute_path(path, buf, buf_len - 1);
		ccs_realpath_unlock();
		path_put(path);
		if (IS_ERR(pos))
			continue;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
		/* Prepend "/proc" prefix if using internal proc vfs mount. */
		if (path->mnt->mnt_flags & MNT_INTERNAL &&
		    path->mnt->mnt_sb->s_magic == PROC_SUPER_MAGIC) {
			pos -= 5;
			if (pos >= buf)
				memmove(pos, "/proc", 5);
			else
				continue;
		}
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 33)
		/* Prepend "/proc" prefix if using internal proc vfs mount. */
		if (path->mnt->mnt_parent == path->mnt &&
		    path->mnt->mnt_sb->s_magic == PROC_SUPER_MAGIC) {
			pos -= 5;
			if (pos >= buf)
				memmove(pos, "/proc", 5);
			else
				continue;
		}
#endif
		name = ccs_encode(pos);
		break;
	}
	kfree(buf);
	if (!name)
		ccs_warn_oom(__func__);
	return name;
}

/**
 * ccs_symlink_path - Get symlink's pathname.
 *
 * @pathname: The pathname to solve.
 * @name:     Pointer to "struct ccs_path_info".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * This function uses kzalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
int ccs_symlink_path(const char *pathname, struct ccs_path_info *name)
{
	char *buf;
	struct path path;
	if (ccs_kern_path(pathname, ccs_lookup_flags ^ LOOKUP_FOLLOW, &path))
		return -ENOENT;
	buf = ccs_realpath_from_path(&path);
	path_put(&path);
	if (buf) {
		name->name = buf;
		ccs_fill_path_info(name);
		return 0;
	}
	return -ENOMEM;
}

/**
 * ccs_encode: Encode binary string to ascii string.
 *
 * @str: String in binary format.
 *
 * Returns pointer to @str in ascii format on success, NULL otherwise.
 *
 * This function uses kzalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
char *ccs_encode(const char *str)
{
	int len = 0;
	const char *p = str;
	char *cp;
	char *cp0;
	if (!p)
		return NULL;
	while (*p) {
		const unsigned char c = *p++;
		if (c == '\\')
			len += 2;
		else if (c > ' ' && c < 127)
			len++;
		else
			len += 4;
	}
	len++;
	/* Reserve space for appending "/". */
	cp = kzalloc(len + 10, CCS_GFP_FLAGS);
	if (!cp)
		return NULL;
	cp0 = cp;
	p = str;
	while (*p) {
		const unsigned char c = *p++;
		if (c == '\\') {
			*cp++ = '\\';
			*cp++ = '\\';
		} else if (c > ' ' && c < 127) {
			*cp++ = c;
		} else {
			*cp++ = '\\';
			*cp++ = (c >> 6) + '0';
			*cp++ = ((c >> 3) & 7) + '0';
			*cp++ = (c & 7) + '0';
		}
	}
	return cp0;
}

/**
 * ccs_get_path - Get dentry/vfsmmount of a pathname.
 *
 * @pathname: The pathname to solve.
 * @path:     Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_get_path(const char *pathname, struct path *path)
{
	return ccs_kern_path(pathname, ccs_lookup_flags, path);
}
