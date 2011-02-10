/*
 * security/ccsecurity/mount.c
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
#include <linux/dcache.h>
#include <linux/namei.h>
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
#include <linux/namespace.h>
#endif
#include "internal.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 15)
#define MS_UNBINDABLE	(1<<17)	/* change to unbindable */
#define MS_PRIVATE	(1<<18)	/* change to private */
#define MS_SLAVE	(1<<19)	/* change to slave */
#define MS_SHARED	(1<<20)	/* change to shared */
#endif

/* Keywords for mount restrictions. */

/* Allow to call 'mount --bind /source_dir /dest_dir' */
#define CCS_MOUNT_BIND_KEYWORD                           "--bind"
/* Allow to call 'mount --move /old_dir    /new_dir ' */
#define CCS_MOUNT_MOVE_KEYWORD                           "--move"
/* Allow to call 'mount -o remount /dir             ' */
#define CCS_MOUNT_REMOUNT_KEYWORD                        "--remount"
/* Allow to call 'mount --make-unbindable /dir'       */
#define CCS_MOUNT_MAKE_UNBINDABLE_KEYWORD                "--make-unbindable"
/* Allow to call 'mount --make-private /dir'          */
#define CCS_MOUNT_MAKE_PRIVATE_KEYWORD                   "--make-private"
/* Allow to call 'mount --make-slave /dir'            */
#define CCS_MOUNT_MAKE_SLAVE_KEYWORD                     "--make-slave"
/* Allow to call 'mount --make-shared /dir'           */
#define CCS_MOUNT_MAKE_SHARED_KEYWORD                    "--make-shared"

/**
 * ccs_audit_mount_log - Audit mount log.
 *
 * @r:          Pointer to "struct ccs_request_info".
 * @dev_name:   Device file.
 * @dir_name:   Mount point.
 * @type:       Filesystem type.
 * @flags:      Mount flags.
 * @is_granted: True if this is a granted log.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_mount_log(struct ccs_request_info *r,
			       const char *dev_name, const char *dir_name,
			       const char *type, const unsigned long flags,
			       const bool is_granted)
{
	if (!is_granted) {
		if (!strcmp(type, CCS_MOUNT_REMOUNT_KEYWORD))
			ccs_warn_log(r, "mount -o remount %s 0x%lX", dir_name,
				     flags);
		else if (!strcmp(type, CCS_MOUNT_BIND_KEYWORD)
			 || !strcmp(type, CCS_MOUNT_MOVE_KEYWORD))
			ccs_warn_log(r, "mount %s %s %s 0x%lX", type, dev_name,
				     dir_name, flags);
		else if (!strcmp(type, CCS_MOUNT_MAKE_UNBINDABLE_KEYWORD) ||
			 !strcmp(type, CCS_MOUNT_MAKE_PRIVATE_KEYWORD) ||
			 !strcmp(type, CCS_MOUNT_MAKE_SLAVE_KEYWORD) ||
			 !strcmp(type, CCS_MOUNT_MAKE_SHARED_KEYWORD))
			ccs_warn_log(r, "mount %s %s 0x%lX", type, dir_name,
				     flags);
		else
			ccs_warn_log(r, "mount -t %s %s %s 0x%lX", type,
				     dev_name, dir_name, flags);
	}
	return ccs_write_audit_log(is_granted, r, CCS_KEYWORD_ALLOW_MOUNT
				   "%s %s %s 0x%lX\n", dev_name, dir_name,
				   type, flags);
}

/**
 * ccs_mount_acl2 - Check permission for mount() operation.
 *
 * @r:        Pointer to "struct ccs_request_info".
 * @dev_name: Name of device file.
 * @dir:      Pointer to "struct path".
 * @type:     Name of filesystem type.
 * @flags:    Mount options.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_mount_acl2(struct ccs_request_info *r, char *dev_name,
			  struct path *dir, char *type, unsigned long flags)
{
	struct ccs_obj_info obj = { };
	struct path path;
	struct ccs_acl_info *ptr;
	struct file_system_type *fstype = NULL;
	const char *requested_type = NULL;
	const char *requested_dir_name = NULL;
	const char *requested_dev_name = NULL;
	struct ccs_path_info rtype;
	struct ccs_path_info rdev;
	struct ccs_path_info rdir;
	int need_dev = 0;
	int error = -ENOMEM;
	const struct ccs_domain_info * const domain = ccs_current_domain();
	r->obj = &obj;

	/* Get fstype. */
	requested_type = ccs_encode(type);
	if (!requested_type)
		goto out;
	rtype.name = requested_type;
	ccs_fill_path_info(&rtype);

	/* Get mount point. */
	obj.path2 = *dir;
	requested_dir_name = ccs_realpath_from_path(dir);
	if (!requested_dir_name) {
		error = -ENOMEM;
		goto out;
	}
	rdir.name = requested_dir_name;
	ccs_fill_path_info(&rdir);

	/* Compare fs name. */
	if (!strcmp(type, CCS_MOUNT_REMOUNT_KEYWORD)) {
		/* dev_name is ignored. */
	} else if (!strcmp(type, CCS_MOUNT_MAKE_UNBINDABLE_KEYWORD) ||
		   !strcmp(type, CCS_MOUNT_MAKE_PRIVATE_KEYWORD) ||
		   !strcmp(type, CCS_MOUNT_MAKE_SLAVE_KEYWORD) ||
		   !strcmp(type, CCS_MOUNT_MAKE_SHARED_KEYWORD)) {
		/* dev_name is ignored. */
	} else if (!strcmp(type, CCS_MOUNT_BIND_KEYWORD) ||
		   !strcmp(type, CCS_MOUNT_MOVE_KEYWORD)) {
		need_dev = -1; /* dev_name is a directory */
	} else {
		fstype = get_fs_type(type);
		if (!fstype) {
			error = -ENODEV;
			goto out;
		}
		if (fstype->fs_flags & FS_REQUIRES_DEV)
			/* dev_name is a block device file. */
			need_dev = 1;
	}
	if (need_dev) {
		/* Get mount point or device file. */
		if (ccs_get_path(dev_name, &path)) {
			error = -ENOENT;
			goto out;
		}
		obj.path1 = path;
		requested_dev_name = ccs_realpath_from_path(&path);
		if (!requested_dev_name) {
			error = -ENOENT;
			goto out;
		}
	} else {
		/* Map dev_name to "<NULL>" if no dev_name given. */
		if (!dev_name)
			dev_name = "<NULL>";
		requested_dev_name = ccs_encode(dev_name);
		if (!requested_dev_name) {
			error = -ENOMEM;
			goto out;
		}
	}
	rdev.name = requested_dev_name;
	ccs_fill_path_info(&rdev);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_mount_acl *acl;
		if (ptr->is_deleted || ptr->type != CCS_TYPE_MOUNT_ACL)
			continue;
		acl = container_of(ptr, struct ccs_mount_acl, head);
		if (!ccs_compare_number_union(flags, &acl->flags) ||
		    !ccs_compare_name_union(&rtype, &acl->fs_type) ||
		    !ccs_compare_name_union(&rdir, &acl->dir_name) ||
		    (need_dev &&
		     !ccs_compare_name_union(&rdev, &acl->dev_name)) ||
		    !ccs_condition(r, ptr))
			continue;
		r->cond = ptr->cond;
		error = 0;
		break;
	}
	ccs_audit_mount_log(r, requested_dev_name, requested_dir_name,
			    requested_type, flags, !error);
	if (error)
		error = ccs_supervisor(r, CCS_KEYWORD_ALLOW_MOUNT
				       "%s %s %s 0x%lX\n",
				       ccs_file_pattern(&rdev),
				       ccs_file_pattern(&rdir),
				       requested_type, flags);
 out:
	kfree(requested_dev_name);
	kfree(requested_dir_name);
	if (fstype)
		ccsecurity_exports.put_filesystem(fstype);
	kfree(requested_type);
	/* Drop refcount obtained by ccs_get_path(). */
	if (obj.path1.dentry)
		path_put(&obj.path1);
	return error;
}

/**
 * ccs_mount_acl - Check permission for mount() operation.
 *
 * @r:        Pointer to "struct ccs_request_info".
 * @dev_name: Name of device file.
 * @dir:      Pointer to "struct path".
 * @type:     Name of filesystem type.
 * @flags:    Mount options.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_mount_acl(struct ccs_request_info *r, char *dev_name,
			 struct path *dir, char *type, unsigned long flags)
{
	int error;
	error = -EPERM;
	if ((flags & MS_MGC_MSK) == MS_MGC_VAL)
		flags &= ~MS_MGC_MSK;
	switch (flags & (MS_REMOUNT | MS_MOVE | MS_BIND)) {
	case MS_REMOUNT:
	case MS_MOVE:
	case MS_BIND:
	case 0:
		break;
	default:
		printk(KERN_WARNING "ERROR: "
		       "%s%s%sare given for single mount operation.\n",
		       flags & MS_REMOUNT ? "'remount' " : "",
		       flags & MS_MOVE    ? "'move' " : "",
		       flags & MS_BIND    ? "'bind' " : "");
		return -EINVAL;
	}
	switch (flags & (MS_UNBINDABLE | MS_PRIVATE | MS_SLAVE | MS_SHARED)) {
	case MS_UNBINDABLE:
	case MS_PRIVATE:
	case MS_SLAVE:
	case MS_SHARED:
	case 0:
		break;
	default:
		printk(KERN_WARNING "ERROR: "
		       "%s%s%s%sare given for single mount operation.\n",
		       flags & MS_UNBINDABLE ? "'unbindable' " : "",
		       flags & MS_PRIVATE    ? "'private' " : "",
		       flags & MS_SLAVE      ? "'slave' " : "",
		       flags & MS_SHARED     ? "'shared' " : "");
		return -EINVAL;
	}
	if (flags & MS_REMOUNT)
		error = ccs_mount_acl(r, dev_name, dir,
				      CCS_MOUNT_REMOUNT_KEYWORD,
				      flags & ~MS_REMOUNT);
	else if (flags & MS_MOVE)
		error = ccs_mount_acl(r, dev_name, dir,
				      CCS_MOUNT_MOVE_KEYWORD,
				      flags & ~MS_MOVE);
	else if (flags & MS_BIND)
		error = ccs_mount_acl(r, dev_name, dir,
				      CCS_MOUNT_BIND_KEYWORD,
				      flags & ~MS_BIND);
	else if (flags & MS_UNBINDABLE)
		error = ccs_mount_acl(r, dev_name, dir,
				      CCS_MOUNT_MAKE_UNBINDABLE_KEYWORD,
				      flags & ~MS_UNBINDABLE);
	else if (flags & MS_PRIVATE)
		error = ccs_mount_acl(r, dev_name, dir,
				      CCS_MOUNT_MAKE_PRIVATE_KEYWORD,
				      flags & ~MS_PRIVATE);
	else if (flags & MS_SLAVE)
		error = ccs_mount_acl(r, dev_name, dir,
				      CCS_MOUNT_MAKE_SLAVE_KEYWORD,
				      flags & ~MS_SLAVE);
	else if (flags & MS_SHARED)
		error = ccs_mount_acl(r, dev_name, dir,
				      CCS_MOUNT_MAKE_SHARED_KEYWORD,
				      flags & ~MS_SHARED);
	else
		do {
			error = ccs_mount_acl2(r, dev_name, dir, type, flags);
		} while (error == CCS_RETRY_REQUEST);
	if (r->mode != CCS_CONFIG_ENFORCING)
		error = 0;
	return error;
}

/**
 * ccs_mount_permission - Check permission for mount() operation.
 *
 * @dev_name:  Name of device file.
 * @path:      Pointer to "struct path".
 * @type:      Name of filesystem type. May be NULL.
 * @flags:     Mount options.
 * @data_page: Optional data. May be NULL.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_mount_permission(char *dev_name, struct path *path,
				  char *type, unsigned long flags,
				  void *data_page)
{
	struct ccs_request_info r;
	int error;
	int idx;
	if (!ccs_capable(CCS_SYS_MOUNT))
		return -EPERM;
	if (ccs_init_request_info(&r, CCS_MAC_FILE_MOUNT)
	    == CCS_CONFIG_DISABLED)
		return 0;
	if (!type)
		type = "<NULL>";
	idx = ccs_read_lock();
	error = ccs_mount_acl(&r, dev_name, path, type, flags);
	ccs_read_unlock(idx);
	return error;
}

/**
 * ccs_write_mount_policy - Write "struct ccs_mount_acl" list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_mount_policy(char *data, struct ccs_domain_info *domain,
			   struct ccs_condition *condition,
			   const bool is_delete)
{
	struct ccs_acl_info *ptr;
	struct ccs_mount_acl e = { .head.type = CCS_TYPE_MOUNT_ACL,
				   .head.cond = condition };
	int error = is_delete ? -ENOENT : -ENOMEM;
	char *w[4];
	if (!ccs_tokenize(data, w, sizeof(w)) || !w[3][0])
		return -EINVAL;
	if (!ccs_parse_name_union(w[0], &e.dev_name) ||
	    !ccs_parse_name_union(w[1], &e.dir_name) ||
	    !ccs_parse_name_union(w[2], &e.fs_type) ||
	    !ccs_parse_number_union(w[3], &e.flags))
		goto out;
	if (mutex_lock_interruptible(&ccs_policy_lock))
		goto out;
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_mount_acl *acl =
			container_of(ptr, struct ccs_mount_acl, head);
		if (!ccs_is_same_mount_acl(acl, &e))
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error) {
		struct ccs_mount_acl *entry = ccs_commit_ok(&e, sizeof(e));
		if (entry) {
			ccs_add_domain_acl(domain, &entry->head);
			error = 0;
		}
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name_union(&e.dev_name);
	ccs_put_name_union(&e.dir_name);
	ccs_put_name_union(&e.fs_type);
	ccs_put_number_union(&e.flags);
	return error;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 24)
static int ccs_old_mount_permission(char *dev_name, struct nameidata *nd,
				    char *type, unsigned long flags,
				    void *data_page)
{
	struct path path = { nd->mnt, nd->dentry };
	return __ccs_mount_permission(dev_name, &path, type, flags, data_page);
}
#endif

void __init ccs_mount_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	ccsecurity_ops.mount_permission = __ccs_mount_permission;
#else
	ccsecurity_ops.mount_permission = ccs_old_mount_permission;
#endif
}
