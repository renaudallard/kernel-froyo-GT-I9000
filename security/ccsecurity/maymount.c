/*
 * security/ccsecurity/maymount.c
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.7.2+   2010/06/04
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/slab.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20)
#include <linux/mount.h>
#include <linux/mnt_namespace.h>
#else
#include <linux/namespace.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
#include <linux/dcache.h>
#include <linux/namei.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
#include <linux/nsproxy.h>
#endif
#include "internal.h"

/**
 * ccs_conceal_mount - Check whether this mount request shadows existing mounts.
 *
 * @path:   Pointer to "struct path".
 * @vfsmnt: Pointer to "struct vfsmount".
 * @dentry: Pointer to "struct dentry".
 *
 * Returns true if @vfsmnt is parent directory compared to @nd,
 * false otherwise.
 */
static bool ccs_conceal_mount(struct path *path, struct vfsmount *vfsmnt,
			      struct dentry *dentry)
{
	while (1) {
		if (path->mnt->mnt_root == vfsmnt->mnt_root &&
		    path->dentry == dentry)
			return true;
		if (dentry == vfsmnt->mnt_root || IS_ROOT(dentry)) {
			if (vfsmnt->mnt_parent == vfsmnt)
				break;
			dentry = vfsmnt->mnt_mountpoint;
			vfsmnt = vfsmnt->mnt_parent;
			continue;
		}
		dentry = dentry->d_parent;
	}
	return false;
}

/**
 * ccs_may_mount - Check whether this mount request shadows existing mounts.
 *
 * @path: Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_may_mount(struct path *path)
{
	struct ccs_request_info r;
	struct list_head *p;
	bool found = false;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
	struct namespace *namespace = current->namespace;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	struct namespace *namespace = current->nsproxy->namespace;
#else
	struct mnt_namespace *namespace = current->nsproxy->mnt_ns;
#endif
	if (!namespace ||
	    ccs_init_request_info(&r, CCS_MAX_MAC_INDEX + CCS_CONCEAL_MOUNT)
	    == CCS_CONFIG_DISABLED)
		return 0;
	found = false;
	list_for_each(p, &namespace->list) {
		struct vfsmount *vfsmnt = list_entry(p, struct vfsmount,
						     mnt_list);
		struct dentry *dentry = vfsmnt->mnt_root;
		ccs_realpath_lock();
		if (IS_ROOT(dentry) || !d_unhashed(dentry))
			found = ccs_conceal_mount(path, vfsmnt, dentry);
		ccs_realpath_unlock();
		if (found)
			break;
	}
	if (!found)
		return 0;
	return ccs_capable(CCS_CONCEAL_MOUNT) ? 0 : -EPERM;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 24)
static int ccs_old_may_mount(struct nameidata *nd)
{
	struct path path = { nd->mnt, nd->dentry };
	return __ccs_may_mount(&path);
}
#endif

void __init ccs_maymount_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	ccsecurity_ops.may_mount = __ccs_may_mount;
#else
	ccsecurity_ops.may_mount = ccs_old_may_mount;
#endif
}
