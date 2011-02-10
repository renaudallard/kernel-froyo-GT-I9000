/*
 * security/ccsecurity/file.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.7.2+   2011/01/21
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include "internal.h"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20)
#include <linux/mount.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
#include <linux/namespace.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
#include <linux/dcache.h>
#include <linux/namei.h>
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 33)
/*
 * ACC_MODE() in this file uses old definition because may_open() receives
 * open flags modified by open_to_namei_flags() until 2.6.33.
 * may_open() receives unmodified flags after 2.6.34.
 */
#undef ACC_MODE
#define ACC_MODE(x) ("\000\004\002\006"[(x)&O_ACCMODE])
#endif

#if defined(RHEL_MAJOR) && RHEL_MAJOR == 6
/* However, RHEL6 passes unmodified flags since 2.6.32-71.14.1.el6 . */
#undef ACC_MODE
#define ACC_MODE(x) ("\004\002\006"[(x)&O_ACCMODE])
#endif

static const char *ccs_path_keyword[CCS_MAX_PATH_OPERATION] = {
	[CCS_TYPE_READ_WRITE] = "read/write",
	[CCS_TYPE_EXECUTE]    = "execute",
	[CCS_TYPE_READ]       = "read",
	[CCS_TYPE_WRITE]      = "write",
	[CCS_TYPE_UNLINK]     = "unlink",
	[CCS_TYPE_RMDIR]      = "rmdir",
	[CCS_TYPE_TRUNCATE]   = "truncate",
	[CCS_TYPE_SYMLINK]    = "symlink",
	[CCS_TYPE_REWRITE]    = "rewrite",
	[CCS_TYPE_CHROOT]     = "chroot",
	[CCS_TYPE_UMOUNT]     = "unmount",
	[CCS_TYPE_TRANSIT]    = "transit",
};

static const char *ccs_path_number3_keyword[CCS_MAX_PATH_NUMBER3_OPERATION] = {
	[CCS_TYPE_MKBLOCK]    = "mkblock",
	[CCS_TYPE_MKCHAR]     = "mkchar",
};

static const char *ccs_path2_keyword[CCS_MAX_PATH2_OPERATION] = {
	[CCS_TYPE_LINK]       = "link",
	[CCS_TYPE_RENAME]     = "rename",
	[CCS_TYPE_PIVOT_ROOT] = "pivot_root",
};

static const char *ccs_path_number_keyword[CCS_MAX_PATH_NUMBER_OPERATION] = {
	[CCS_TYPE_CREATE] = "create",
	[CCS_TYPE_MKDIR]  = "mkdir",
	[CCS_TYPE_MKFIFO] = "mkfifo",
	[CCS_TYPE_MKSOCK] = "mksock",
	[CCS_TYPE_IOCTL]  = "ioctl",
	[CCS_TYPE_CHMOD]  = "chmod",
	[CCS_TYPE_CHOWN]  = "chown",
	[CCS_TYPE_CHGRP]  = "chgrp",
};

static const u8 ccs_p2mac[CCS_MAX_PATH_OPERATION] = {
	[CCS_TYPE_READ_WRITE] = CCS_MAC_FILE_OPEN,
	[CCS_TYPE_EXECUTE]    = CCS_MAC_FILE_EXECUTE,
	[CCS_TYPE_READ]       = CCS_MAC_FILE_OPEN,
	[CCS_TYPE_WRITE]      = CCS_MAC_FILE_OPEN,
	[CCS_TYPE_UNLINK]     = CCS_MAC_FILE_UNLINK,
	[CCS_TYPE_RMDIR]      = CCS_MAC_FILE_RMDIR,
	[CCS_TYPE_TRUNCATE]   = CCS_MAC_FILE_TRUNCATE,
	[CCS_TYPE_SYMLINK]    = CCS_MAC_FILE_SYMLINK,
	[CCS_TYPE_REWRITE]    = CCS_MAC_FILE_REWRITE,
	[CCS_TYPE_CHROOT]     = CCS_MAC_FILE_CHROOT,
	[CCS_TYPE_UMOUNT]     = CCS_MAC_FILE_UMOUNT,
	[CCS_TYPE_TRANSIT]    = CCS_MAC_FILE_TRANSIT,
};

static const u8 ccs_pnnn2mac[CCS_MAX_PATH_NUMBER3_OPERATION] = {
	[CCS_TYPE_MKBLOCK] = CCS_MAC_FILE_MKBLOCK,
	[CCS_TYPE_MKCHAR]  = CCS_MAC_FILE_MKCHAR,
};

static const u8 ccs_pp2mac[CCS_MAX_PATH2_OPERATION] = {
	[CCS_TYPE_LINK]       = CCS_MAC_FILE_LINK,
	[CCS_TYPE_RENAME]     = CCS_MAC_FILE_RENAME,
	[CCS_TYPE_PIVOT_ROOT] = CCS_MAC_FILE_PIVOT_ROOT,
};

static const u8 ccs_pn2mac[CCS_MAX_PATH_NUMBER_OPERATION] = {
	[CCS_TYPE_CREATE] = CCS_MAC_FILE_CREATE,
	[CCS_TYPE_MKDIR]  = CCS_MAC_FILE_MKDIR,
	[CCS_TYPE_MKFIFO] = CCS_MAC_FILE_MKFIFO,
	[CCS_TYPE_MKSOCK] = CCS_MAC_FILE_MKSOCK,
	[CCS_TYPE_IOCTL]  = CCS_MAC_FILE_IOCTL,
	[CCS_TYPE_CHMOD]  = CCS_MAC_FILE_CHMOD,
	[CCS_TYPE_CHOWN]  = CCS_MAC_FILE_CHOWN,
	[CCS_TYPE_CHGRP]  = CCS_MAC_FILE_CHGRP,
};

/* Main functions. */

void ccs_put_name_union(struct ccs_name_union *ptr)
{
	if (!ptr)
		return;
	if (ptr->is_group)
		ccs_put_path_group(ptr->group);
	else
		ccs_put_name(ptr->filename);
}

void ccs_put_number_union(struct ccs_number_union *ptr)
{
	if (ptr && ptr->is_group)
		ccs_put_number_group(ptr->group);
}

bool ccs_compare_number_union(const unsigned long value,
			      const struct ccs_number_union *ptr)
{
	if (ptr->is_group)
		return ccs_number_matches_group(value, value, ptr->group);
	return value >= ptr->values[0] && value <= ptr->values[1];
}

bool ccs_compare_name_union(const struct ccs_path_info *name,
			    const struct ccs_name_union *ptr)
{
	if (ptr->is_group)
		return ccs_path_matches_group(name, ptr->group, 1);
	return ccs_path_matches_pattern(name, ptr->filename);
}

static bool ccs_compare_name_union_pattern(const struct ccs_path_info *name,
					   const struct ccs_name_union *ptr,
					   const bool may_use_pattern)
{
	if (ptr->is_group)
		return ccs_path_matches_group(name, ptr->group,
					      may_use_pattern);
	if (may_use_pattern || !ptr->filename->is_patterned)
		return ccs_path_matches_pattern(name, ptr->filename);
	return false;
}

/**
 * ccs_path2keyword - Get the name of path operations.
 *
 * @operation: Type of operation.
 *
 * Returns the name of path operation.
 */
const char *ccs_path2keyword(const u8 operation)
{
	return (operation < CCS_MAX_PATH_OPERATION)
		? ccs_path_keyword[operation] : NULL;
}

/**
 * ccs_path_number32keyword - Get the name of path/number/number/number operations.
 *
 * @operation: Type of operation.
 *
 * Returns the name of path/number/number/number operation.
 */
const char *ccs_path_number32keyword(const u8 operation)
{
	return (operation < CCS_MAX_PATH_NUMBER3_OPERATION)
		? ccs_path_number3_keyword[operation] : NULL;
}

/**
 * ccs_path22keyword - Get the name of path/path operations.
 *
 * @operation: Type of operation.
 *
 * Returns the name of path/path operation.
 */
const char *ccs_path22keyword(const u8 operation)
{
	return (operation < CCS_MAX_PATH2_OPERATION)
		? ccs_path2_keyword[operation] : NULL;
}

/**
 * ccs_path_number2keyword - Get the name of path/number operations.
 *
 * @operation: Type of operation.
 *
 * Returns the name of path/number operation.
 */
const char *ccs_path_number2keyword(const u8 operation)
{
	return (operation < CCS_MAX_PATH_NUMBER_OPERATION)
		? ccs_path_number_keyword[operation] : NULL;
}

static void ccs_add_slash(struct ccs_path_info *buf)
{
	if (buf->is_dir)
		return;
	/* This is OK because ccs_encode() reserves space for appending "/". */
	strcat((char *) buf->name, "/");
	ccs_fill_path_info(buf);
}

/**
 * ccs_strendswith - Check whether the token ends with the given token.
 *
 * @name: The token to check.
 * @tail: The token to find.
 *
 * Returns true if @name ends with @tail, false otherwise.
 */
static bool ccs_strendswith(const char *name, const char *tail)
{
	int len;
	if (!name || !tail)
		return false;
	len = strlen(name) - strlen(tail);
	return len >= 0 && !strcmp(name + len, tail);
}

/**
 * ccs_get_realpath - Get realpath.
 *
 * @buf:    Pointer to "struct ccs_path_info".
 * @dentry: Pointer to "struct dentry".
 * @mnt:    Pointer to "struct vfsmount".
 *
 * Returns true success, false otherwise.
 */
static bool ccs_get_realpath(struct ccs_path_info *buf, struct dentry *dentry,
			     struct vfsmount *mnt)
{
	struct path path = { mnt, dentry };
	buf->name = ccs_realpath_from_path(&path);
	if (buf->name) {
		ccs_fill_path_info(buf);
		return true;
	}
	return false;
}

static int ccs_update_path_acl(const u8 type, const char *filename,
			       struct ccs_domain_info * const domain,
			       struct ccs_condition *condition,
			       const bool is_delete);

/**
 * ccs_audit_path_log - Audit path request log.
 *
 * @r:          Pointer to "struct ccs_request_info".
 * @operation:  The name of operation.
 * @filename:   Pathname.
 * @is_granted: True if this is a granted log.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_path_log(struct ccs_request_info *r,
			      const char *operation, const char *filename,
			      const bool is_granted)
{
	if (!is_granted)
		ccs_warn_log(r, "%s %s", operation, filename);
	return ccs_write_audit_log(is_granted, r, "allow_%s %s\n", operation,
				   filename);
}

/**
 * ccs_audit_path2_log - Audit path/path request log.
 *
 * @r:          Pointer to "struct ccs_request_info".
 * @operation:  The name of operation.
 * @filename1:  First pathname.
 * @filename2:  Second pathname.
 * @is_granted: True if this is a granted log.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_path2_log(struct ccs_request_info *r,
			       const char *operation, const char *filename1,
			       const char *filename2, const bool is_granted)
{
	if (!is_granted)
		ccs_warn_log(r, "%s %s %s", operation, filename1, filename2);
	return ccs_write_audit_log(is_granted, r, "allow_%s %s %s\n",
				   operation, filename1, filename2);
}

/**
 * ccs_audit_path_number3_log - Audit path/number/number/number request log.
 *
 * @r:          Pointer to "struct ccs_request_info".
 * @operation:  The name of operation.
 * @filename:   First pathname.
 * @mode:       Create mode.
 * @major:      Device major number.
 * @minor:      Device minor number.
 * @is_granted: True if this is a granted log.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_path_number3_log(struct ccs_request_info *r,
				      const char *operation,
				      const char *filename,
				      const unsigned int mode,
				      const unsigned int major,
				      const unsigned int minor,
				      const bool is_granted)
{
	if (!is_granted)
		ccs_warn_log(r, "%s %s 0%o %u %u", operation, filename, mode,
			     major, minor);
	return ccs_write_audit_log(is_granted, r, "allow_%s %s 0%o %u %u\n",
				   operation, filename, mode, major, minor);
}

/**
 * ccs_audit_path_number_log - Audit path/number request log.
 *
 * @r:          Pointer to "struct ccs_request_info".
 * @type:       Type of operation.
 * @filename:   Pathname.
 * @value:      Value.
 * @is_granted: True if this is a granted log.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_path_number_log(struct ccs_request_info *r,
				     const char *operation,
				     const char *filename, const char *value,
				     const bool is_granted)
{
	if (!is_granted)
		ccs_warn_log(r, "%s %s %s", operation, filename, value);
	return ccs_write_audit_log(is_granted, r, "allow_%s %s %s\n",
				   operation, filename, value);
}

/* The list for "struct ccs_globally_readable_file_entry". */
LIST_HEAD(ccs_globally_readable_list);

/**
 * ccs_is_globally_readable_file - Check if the file is unconditionnaly permitted to be open()ed for reading.
 *
 * @filename: The filename to check.
 *
 * Returns true if any domain can open @filename for reading, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_is_globally_readable_file(const struct ccs_path_info *filename)
{
	struct ccs_globally_readable_file_entry *ptr;
	bool found = false;
	list_for_each_entry_rcu(ptr, &ccs_globally_readable_list, list) {
		if (ptr->is_deleted ||
		    !ccs_path_matches_pattern(filename, ptr->filename))
			continue;
		found = true;
		break;
	}
	return found;
}

/**
 * ccs_write_globally_readable_policy - Write "struct ccs_globally_readable_file_entry" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_globally_readable_policy(char *data, const bool is_delete)
{
	struct ccs_globally_readable_file_entry *ptr;
	struct ccs_globally_readable_file_entry e = { };
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!ccs_is_correct_path(data, 1, 0, -1))
		return -EINVAL;
	e.filename = ccs_get_name(data);
	if (!e.filename)
		return -ENOMEM;
	if (mutex_lock_interruptible(&ccs_policy_lock))
		goto out;
	list_for_each_entry_rcu(ptr, &ccs_globally_readable_list, list) {
		if (ptr->filename != e.filename)
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error) {
		struct ccs_globally_readable_file_entry *entry =
			ccs_commit_ok(&e, sizeof(e));
		if (entry) {
			list_add_tail_rcu(&entry->list,
					  &ccs_globally_readable_list);
			error = 0;
		}
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name(e.filename);
	return error;
}

/**
 * ccs_read_globally_readable_policy - Read "struct ccs_globally_readable_file_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_read_globally_readable_policy(struct ccs_io_buffer *head)
{
	struct list_head *pos;
	bool done = true;
	list_for_each_cookie(pos, head->read_var2,
			     &ccs_globally_readable_list) {
		struct ccs_globally_readable_file_entry *ptr;
		ptr = list_entry(pos, struct ccs_globally_readable_file_entry,
				 list);
		if (ptr->is_deleted)
			continue;
		done = ccs_io_printf(head, CCS_KEYWORD_ALLOW_READ "%s\n",
				     ptr->filename->name);
		if (!done)
			break;
	}
	return done;
}

/* The list for "struct ccs_pattern_entry". */
LIST_HEAD(ccs_pattern_list);

/**
 * ccs_file_pattern - Get patterned pathname.
 *
 * @filename: Pointer to "struct ccs_path_info".
 *
 * Returns pointer to patterned pathname.
 *
 * Caller holds ccs_read_lock().
 */
const char *ccs_file_pattern(const struct ccs_path_info *filename)
{
	struct ccs_pattern_entry *ptr;
	const struct ccs_path_info *pattern = NULL;
	list_for_each_entry_rcu(ptr, &ccs_pattern_list, list) {
		if (ptr->is_deleted)
			continue;
		if (!ccs_path_matches_pattern(filename, ptr->pattern))
			continue;
		pattern = ptr->pattern;
		if (ccs_strendswith(pattern->name, "/\\*")) {
			/* Do nothing. Try to find the better match. */
		} else {
			/* This would be the better match. Use this. */
			break;
		}
	}
	return pattern ? pattern->name : filename->name;
}

/**
 * ccs_write_pattern_policy - Write "struct ccs_pattern_entry" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_pattern_policy(char *data, const bool is_delete)
{
	struct ccs_pattern_entry *ptr;
	struct ccs_pattern_entry e = { };
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!ccs_is_correct_path(data, 0, 1, 0))
		return -EINVAL;
	e.pattern = ccs_get_name(data);
	if (!e.pattern)
		return error;
	if (mutex_lock_interruptible(&ccs_policy_lock))
		goto out;
	list_for_each_entry_rcu(ptr, &ccs_pattern_list, list) {
		if (e.pattern != ptr->pattern)
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error) {
		struct ccs_pattern_entry *entry = ccs_commit_ok(&e, sizeof(e));
		if (entry) {
			list_add_tail_rcu(&entry->list, &ccs_pattern_list);
			error = 0;
		}
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name(e.pattern);
	return error;
}

/**
 * ccs_read_file_pattern - Read "struct ccs_pattern_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_read_file_pattern(struct ccs_io_buffer *head)
{
	struct list_head *pos;
	bool done = true;
	list_for_each_cookie(pos, head->read_var2, &ccs_pattern_list) {
		struct ccs_pattern_entry *ptr;
		ptr = list_entry(pos, struct ccs_pattern_entry, list);
		if (ptr->is_deleted)
			continue;
		done = ccs_io_printf(head, CCS_KEYWORD_FILE_PATTERN "%s\n",
				     ptr->pattern->name);
		if (!done)
			break;
	}
	return done;
}

/* The list for "struct ccs_no_rewrite_entry". */
LIST_HEAD(ccs_no_rewrite_list);

/**
 * ccs_is_no_rewrite_file - Check if the given pathname is not permitted to be rewrited.
 *
 * @filename: Filename to check.
 *
 * Returns true if @filename is specified by "deny_rewrite" directive,
 * false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_is_no_rewrite_file(const struct ccs_path_info *filename)
{
	struct ccs_no_rewrite_entry *ptr;
	bool matched = false;
	list_for_each_entry_rcu(ptr, &ccs_no_rewrite_list, list) {
		if (ptr->is_deleted)
			continue;
		if (!ccs_path_matches_pattern(filename, ptr->pattern))
			continue;
		matched = true;
		break;
	}
	return matched;
}

/**
 * ccs_write_no_rewrite_policy - Write "struct ccs_no_rewrite_entry" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_no_rewrite_policy(char *data, const bool is_delete)
{
	struct ccs_no_rewrite_entry *ptr;
	struct ccs_no_rewrite_entry e = { };
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!ccs_is_correct_path(data, 0, 0, 0))
		return -EINVAL;
	e.pattern = ccs_get_name(data);
	if (!e.pattern)
		return error;
	if (mutex_lock_interruptible(&ccs_policy_lock))
		goto out;
	list_for_each_entry_rcu(ptr, &ccs_no_rewrite_list, list) {
		if (ptr->pattern != e.pattern)
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error) {
		struct ccs_no_rewrite_entry *entry =
			ccs_commit_ok(&e, sizeof(e));
		if (entry) {
			list_add_tail_rcu(&entry->list, &ccs_no_rewrite_list);
			error = 0;
		}
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name(e.pattern);
	return error;
}

/**
 * ccs_read_no_rewrite_policy - Read "struct ccs_no_rewrite_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_read_no_rewrite_policy(struct ccs_io_buffer *head)
{
	struct list_head *pos;
	bool done = true;
	list_for_each_cookie(pos, head->read_var2, &ccs_no_rewrite_list) {
		struct ccs_no_rewrite_entry *ptr;
		ptr = list_entry(pos, struct ccs_no_rewrite_entry, list);
		if (ptr->is_deleted)
			continue;
		done = ccs_io_printf(head, CCS_KEYWORD_DENY_REWRITE "%s\n",
				     ptr->pattern->name);
		if (!done)
			break;
	}
	return done;
}

/**
 * ccs_update_file_acl - Update file's read/write/execute ACL.
 *
 * @perm:      Permission (between 1 to 7).
 * @filename:  Filename.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * This is legacy support interface for older policy syntax.
 * Current policy syntax uses "allow_read/write" instead of "6",
 * "allow_read" instead of "4", "allow_write" instead of "2",
 * "allow_execute" instead of "1".
 */
static inline int ccs_update_file_acl(u8 perm, const char *filename,
				      struct ccs_domain_info * const domain,
				      struct ccs_condition *condition,
				      const bool is_delete)
{
	if (perm > 7 || !perm)
		return -EINVAL;
	if (filename[0] != '@' && ccs_strendswith(filename, "/"))
		/*
		 * Only 'allow_mkdir' and 'allow_rmdir' are valid for
		 * directory permissions.
		 */
		return 0;
	if (perm & 4)
		ccs_update_path_acl(CCS_TYPE_READ, filename, domain,
				    condition, is_delete);
	if (perm & 2)
		ccs_update_path_acl(CCS_TYPE_WRITE, filename,
				    domain, condition, is_delete);
	if (perm & 1)
		ccs_update_path_acl(CCS_TYPE_EXECUTE, filename,
				    domain, condition, is_delete);
	return 0;
}

/**
 * ccs_path_acl - Check permission for path operation.
 *
 * @r:               Pointer to "struct ccs_request_info".
 * @filename:        Filename to check.
 * @perm:            Permission.
 * @may_use_pattern: True if patterned ACL is permitted.
 *
 * Returns 0 on success, -EPERM otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_path_acl(struct ccs_request_info *r,
			const struct ccs_path_info *filename,
			const u16 perm, const bool may_use_pattern)
{
	const struct ccs_domain_info * const domain = ccs_current_domain();
	struct ccs_acl_info *ptr;
	int error = -EPERM;
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_path_acl *acl;
		if (ptr->is_deleted || ptr->type != CCS_TYPE_PATH_ACL)
			continue;
		acl = container_of(ptr, struct ccs_path_acl, head);
		if (!(acl->perm & perm) || !ccs_condition(r, ptr) ||
		    !ccs_compare_name_union_pattern(filename, &acl->name,
						    may_use_pattern))
			continue;
		r->cond = ptr->cond;
		error = 0;
		break;
	}
	return error;
}

/**
 * ccs_path_number3_acl - Check permission for path/number/number/number operation.
 *
 * @r:        Pointer to "struct ccs_request_info".
 * @filename: Filename to check.
 * @perm:     Permission.
 * @mode:     Create mode.
 * @major:    Device major number.
 * @minor:    Device minor number.
 *
 * Returns 0 on success, -EPERM otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_path_number3_acl(struct ccs_request_info *r,
				const struct ccs_path_info *filename,
				const u16 perm, const unsigned int mode,
				const unsigned int major,
				const unsigned int minor)
{
	const struct ccs_domain_info * const domain = ccs_current_domain();
	struct ccs_acl_info *ptr;
	int error = -EPERM;
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_path_number3_acl *acl;
		if (ptr->is_deleted || ptr->type != CCS_TYPE_PATH_NUMBER3_ACL)
			continue;
		acl = container_of(ptr, struct ccs_path_number3_acl, head);
		if (!ccs_compare_number_union(mode, &acl->mode))
			continue;
		if (!ccs_compare_number_union(major, &acl->major))
			continue;
		if (!ccs_compare_number_union(minor, &acl->minor))
			continue;
		if (!(acl->perm & perm) || !ccs_condition(r, ptr))
			continue;
		if (!ccs_compare_name_union(filename, &acl->name))
			continue;
		r->cond = ptr->cond;
		error = 0;
		break;
	}
	return error;
}

/**
 * ccs_file_perm - Check permission for opening files.
 *
 * @r:         Pointer to "struct ccs_request_info".
 * @filename:  Filename to check.
 * @mode:      Mode ("read" or "write" or "read/write" or "execute").
 *
 * Returns 0 on success, 1 on retry, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_file_perm(struct ccs_request_info *r,
			 const struct ccs_path_info *filename, const u8 mode)
{
	const char *msg = "<unknown>";
	int error = 0;
	u16 perm = 0;
	const struct ccs_domain_info * const domain = ccs_current_domain();
	if (!filename)
		return 0;
	if (mode == 6) {
		msg = ccs_path2keyword(CCS_TYPE_READ_WRITE);
		perm = 1 << CCS_TYPE_READ_WRITE;
	} else if (mode == 4) {
		msg = ccs_path2keyword(CCS_TYPE_READ);
		perm = 1 << CCS_TYPE_READ;
	} else if (mode == 2) {
		msg = ccs_path2keyword(CCS_TYPE_WRITE);
		perm = 1 << CCS_TYPE_WRITE;
	} else if (mode == 1) {
		msg = ccs_path2keyword(CCS_TYPE_EXECUTE);
		perm = 1 << CCS_TYPE_EXECUTE;
	} else
		BUG();
	do {
		error = ccs_path_acl(r, filename, perm, mode != 1);
		if (error && mode == 4 && !domain->ignore_global_allow_read
		    && ccs_is_globally_readable_file(filename))
			error = 0;
		ccs_audit_path_log(r, msg, filename->name, !error);
		if (!error)
			break;
		error = ccs_supervisor(r, "allow_%s %s\n", msg,
				       mode == 1 ? filename->name :
				       ccs_file_pattern(filename));
		/*
		 * Do not retry for execute request, for aggregator may have
		 * changed.
		 */
	} while (error == CCS_RETRY_REQUEST && !r->ee);
	if (r->mode != CCS_CONFIG_ENFORCING)
		error = 0;
	return error;
}

/**
 * ccs_update_execute_handler - Update "struct ccs_execute_handler_record" list.
 *
 * @type:      Type of execute handler.
 * @filename:  Pathname to the execute handler.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static inline int ccs_update_execute_handler(const u8 type,
					     const char *filename,
					     struct ccs_domain_info * const
					     domain, const bool is_delete)
{
	struct ccs_acl_info *ptr;
	struct ccs_execute_handler_record e = { .head.type = type };
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!domain)
		return -EINVAL;
	if (!ccs_is_correct_path(filename, 1, -1, -1))
		return -EINVAL;
	e.handler = ccs_get_name(filename);
	if (!e.handler)
		return -ENOMEM;
	if (mutex_lock_interruptible(&ccs_policy_lock))
		goto out;
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_execute_handler_record *acl;
		if (ptr->type != type)
			continue;
		/* Condition not supported. */
		acl = container_of(ptr, struct ccs_execute_handler_record,
				   head);
		if (acl->handler != e.handler)
			continue;
		if (!is_delete) {
			/* Only one entry can exist in a domain. */
			struct ccs_acl_info *ptr2;
			list_for_each_entry_rcu(ptr2, &domain->acl_info_list,
						list) {
				if (ptr2->type == type)
					ptr2->is_deleted = true;
			}
		}
		ptr->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error) {
		struct ccs_execute_handler_record *entry =
			ccs_commit_ok(&e, sizeof(e));
		if (entry) {
			/* Only one entry can exist in a domain. */
			list_for_each_entry_rcu(ptr, &domain->acl_info_list,
						list) {
				if (ptr->type == type)
					ptr->is_deleted = true;
			}
			ccs_add_domain_acl(domain, &entry->head);
			error = 0;
		}
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name(e.handler);
	return error;
}

/**
 * ccs_update_path_acl - Update "struct ccs_path_acl" list.
 *
 * @type:      Type of operation.
 * @filename:  Filename.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_path_acl(const u8 type, const char *filename,
			       struct ccs_domain_info * const domain,
			       struct ccs_condition *condition,
			       const bool is_delete)
{
	static const u16 ccs_rw_mask =
		(1 << CCS_TYPE_READ) | (1 << CCS_TYPE_WRITE);
	const u16 perm = 1 << type;
	struct ccs_acl_info *ptr;
	struct ccs_path_acl e = {
		.head.type = CCS_TYPE_PATH_ACL,
		.head.cond = condition,
		.perm = perm
	};
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (type == CCS_TYPE_READ_WRITE)
		e.perm |= ccs_rw_mask;
	if (!ccs_parse_name_union(filename, &e.name))
		return -EINVAL;
	if (mutex_lock_interruptible(&ccs_policy_lock))
		goto out;
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_path_acl *acl =
			container_of(ptr, struct ccs_path_acl, head);
		if (!ccs_is_same_path_acl(acl, &e))
			continue;
		if (is_delete) {
			acl->perm &= ~perm;
			if ((acl->perm & ccs_rw_mask) != ccs_rw_mask)
				acl->perm &= ~(1 << CCS_TYPE_READ_WRITE);
			else if (!(acl->perm & (1 << CCS_TYPE_READ_WRITE)))
				acl->perm &= ~ccs_rw_mask;
			if (!acl->perm)
				ptr->is_deleted = true;
		} else {
			if (ptr->is_deleted)
				acl->perm = 0;
			acl->perm |= perm;
			if ((acl->perm & ccs_rw_mask) == ccs_rw_mask)
				acl->perm |= 1 << CCS_TYPE_READ_WRITE;
			else if (acl->perm & (1 << CCS_TYPE_READ_WRITE))
				acl->perm |= ccs_rw_mask;
			ptr->is_deleted = false;
		}
		error = 0;
		break;
	}
	if (!is_delete && error) {
		struct ccs_path_acl *entry = ccs_commit_ok(&e, sizeof(e));
		if (entry) {
			ccs_add_domain_acl(domain, &entry->head);
			error = 0;
		}
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name_union(&e.name);
	return error;
}

/**
 * ccs_update_path_number3_acl - Update "struct ccs_path_number3_acl" list.
 *
 * @type:      Type of operation.
 * @filename:  Filename.
 * @mode:      Create mode.
 * @major:     Device major number.
 * @minor:     Device minor number.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static inline int ccs_update_path_number3_acl(const u8 type,
					      const char *filename, char *mode,
					      char *major, char *minor,
					      struct ccs_domain_info * const
					      domain,
					      struct ccs_condition *condition,
					      const bool is_delete)
{
	const u8 perm = 1 << type;
	struct ccs_acl_info *ptr;
	struct ccs_path_number3_acl e = {
		.head.type = CCS_TYPE_PATH_NUMBER3_ACL,
		.head.cond = condition,
		.perm = perm
	};
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!ccs_parse_name_union(filename, &e.name) ||
	    !ccs_parse_number_union(mode, &e.mode) ||
	    !ccs_parse_number_union(major, &e.major) ||
	    !ccs_parse_number_union(minor, &e.minor))
		goto out;
	if (mutex_lock_interruptible(&ccs_policy_lock))
		goto out;
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_path_number3_acl *acl =
			container_of(ptr, struct ccs_path_number3_acl, head);
		if (!ccs_is_same_path_number3_acl(acl, &e))
			continue;
		if (is_delete) {
			acl->perm &= ~perm;
			if (!acl->perm)
				ptr->is_deleted = true;
		} else {
			if (ptr->is_deleted)
				acl->perm = 0;
			acl->perm |= perm;
			ptr->is_deleted = false;
		}
		error = 0;
		break;
	}
	if (!is_delete && error) {
		struct ccs_path_number3_acl *entry =
			ccs_commit_ok(&e, sizeof(e));
		if (entry) {
			ccs_add_domain_acl(domain, &entry->head);
			error = 0;
		}
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name_union(&e.name);
	ccs_put_number_union(&e.mode);
	ccs_put_number_union(&e.major);
	ccs_put_number_union(&e.minor);
	return error;
}

/**
 * ccs_update_path2_acl - Update "struct ccs_path2_acl" list.
 *
 * @type:      Type of operation.
 * @filename1: First filename.
 * @filename2: Second filename.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static inline int ccs_update_path2_acl(const u8 type, const char *filename1,
				       const char *filename2,
				       struct ccs_domain_info * const domain,
				       struct ccs_condition *condition,
				       const bool is_delete)
{
	const u8 perm = 1 << type;
	struct ccs_acl_info *ptr;
	struct ccs_path2_acl e = {
		.head.type = CCS_TYPE_PATH2_ACL,
		.head.cond = condition,
		.perm = perm
	};
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!ccs_parse_name_union(filename1, &e.name1) ||
	    !ccs_parse_name_union(filename2, &e.name2))
		goto out;
	if (mutex_lock_interruptible(&ccs_policy_lock))
		goto out;
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_path2_acl *acl =
			container_of(ptr, struct ccs_path2_acl, head);
		if (!ccs_is_same_path2_acl(acl, &e))
			continue;
		if (is_delete) {
			acl->perm &= ~perm;
			if (!acl->perm)
				ptr->is_deleted = true;
		} else {
			if (ptr->is_deleted)
				acl->perm = 0;
			acl->perm |= perm;
			ptr->is_deleted = false;
		}
		error = 0;
		break;
	}
	if (!is_delete && error) {
		struct ccs_path2_acl *entry = ccs_commit_ok(&e, sizeof(e));
		if (entry) {
			ccs_add_domain_acl(domain, &entry->head);
			error = 0;
		}
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name_union(&e.name1);
	ccs_put_name_union(&e.name2);
	return error;
}

/**
 * ccs_path2_acl - Check permission for path/path operation.
 *
 * @r:         Pointer to "struct ccs_request_info".
 * @type:      Type of operation.
 * @filename1: First filename to check.
 * @filename2: Second filename to check.
 *
 * Returns 0 on success, -EPERM otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_path2_acl(struct ccs_request_info *r, const u8 type,
			 const struct ccs_path_info *filename1,
			 const struct ccs_path_info *filename2)
{
	const struct ccs_domain_info * const domain = ccs_current_domain();
	struct ccs_acl_info *ptr;
	const u8 perm = 1 << type;
	int error = -EPERM;
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_path2_acl *acl;
		if (ptr->is_deleted || ptr->type != CCS_TYPE_PATH2_ACL)
			continue;
		acl = container_of(ptr, struct ccs_path2_acl, head);
		if (!(acl->perm & perm) || !ccs_condition(r, ptr) ||
		    !ccs_compare_name_union(filename1, &acl->name1) ||
		    !ccs_compare_name_union(filename2, &acl->name2))
			continue;
		r->cond = ptr->cond;
		error = 0;
		break;
	}
	return error;
}

/**
 * ccs_path_permission - Check permission for path operation.
 *
 * @r:         Pointer to "struct ccs_request_info".
 * @operation: Type of operation.
 * @filename:  Filename to check.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
int ccs_path_permission(struct ccs_request_info *r, u8 operation,
			const struct ccs_path_info *filename)
{
	const char *msg;
	int error;
 repeat:
	r->type = ccs_p2mac[operation];
	r->mode = ccs_get_mode(r->profile, r->type);
	if (r->mode == CCS_CONFIG_DISABLED)
		return 0;
	do {
		error = ccs_path_acl(r, filename, 1 << operation,
				     operation != CCS_TYPE_TRANSIT);
		msg = ccs_path2keyword(operation);
		ccs_audit_path_log(r, msg, filename->name, !error);
		if (!error)
			break;
		error = ccs_supervisor(r, "allow_%s %s\n", msg,
				       ccs_file_pattern(filename));
	} while (error == CCS_RETRY_REQUEST);
	if (r->mode != CCS_CONFIG_ENFORCING)
		error = 0;
	/*
	 * Since "allow_truncate" doesn't imply "allow_rewrite" permission,
	 * we need to check "allow_rewrite" permission if the filename is
	 * specified by "deny_rewrite" keyword.
	 */
	if (!error && operation == CCS_TYPE_TRUNCATE &&
	    ccs_is_no_rewrite_file(filename)) {
		operation = CCS_TYPE_REWRITE;
		goto repeat;
	}
	return error;
}

/**
 * ccs_path_number3_perm2 - Check permission for path/number/number/number operation.
 *
 * @r:         Pointer to "struct ccs_request_info".
 * @operation: Type of operation.
 * @filename:  Filename to check.
 * @mode:      Create mode.
 * @dev:       Device number.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_path_number3_perm2(struct ccs_request_info *r,
				  const u8 operation,
				  const struct ccs_path_info *filename,
				  const unsigned int mode,
				  const unsigned int dev)
{
	int error;
	const char *msg = ccs_path_number32keyword(operation);
	const unsigned int major = MAJOR(dev);
	const unsigned int minor = MINOR(dev);
	if (!r->mode)
		return 0;
	do {
		error = ccs_path_number3_acl(r, filename, 1 << operation, mode,
					     major, minor);
		ccs_audit_path_number3_log(r, msg, filename->name, mode, major,
					   minor, !error);
		if (!error)
			break;
		error = ccs_supervisor(r, "allow_%s %s 0%o %u %u\n", msg,
				       ccs_file_pattern(filename), mode,
				       major, minor);
	} while (error == CCS_RETRY_REQUEST);
	if (r->mode != CCS_CONFIG_ENFORCING)
		error = 0;
	return error;
}

/**
 * ccs_exec_perm - Check permission for "execute".
 *
 * @r:        Pointer to "struct ccs_request_info".
 * @filename: Check permission for "execute".
 *
 * Returns 0 on success, 1 on retry, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
int ccs_exec_perm(struct ccs_request_info *r,
		  const struct ccs_path_info *filename)
{
	if (r->mode == CCS_CONFIG_DISABLED)
		return 0;
	return ccs_file_perm(r, filename, 1);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 34)
/*
 * Save original flags passed to sys_open().
 *
 * TOMOYO does not check "allow_write" if open(path, O_TRUNC | O_RDONLY) was
 * requested because write() is not permitted. Instead, TOMOYO checks
 * "allow_truncate" if O_TRUNC is passed.
 *
 * TOMOYO does not check "allow_read/write" if open(path, 3) was requested
 * because read()/write() are not permitted. Instead, TOMOYO checks
 * "allow_ioctl" when ioctl() is requested.
 */
static void __ccs_save_open_mode(int mode)
{
	if ((mode & 3) == 3)
		current->ccs_flags |= CCS_OPEN_FOR_IOCTL_ONLY;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 14)
	/* O_TRUNC passes MAY_WRITE to ccs_open_permission(). */
	else if (!(mode & 3) && (mode & O_TRUNC))
		current->ccs_flags |= CCS_OPEN_FOR_READ_TRUNCATE;
#endif
}

static void __ccs_clear_open_mode(void)
{
	current->ccs_flags &= ~(CCS_OPEN_FOR_IOCTL_ONLY |
				CCS_OPEN_FOR_READ_TRUNCATE);
}
#endif

/**
 * ccs_open_permission - Check permission for "read" and "write".
 *
 * @dentry: Pointer to "struct dentry".
 * @mnt:    Pointer to "struct vfsmount".
 * @flag:   Flags for open().
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_open_permission(struct dentry *dentry, struct vfsmount *mnt,
				 const int flag)
{
	struct ccs_request_info r;
	struct ccs_obj_info obj = {
		.path1.dentry = dentry,
		.path1.mnt = mnt
	};
	struct task_struct * const task = current;
	const u32 ccs_flags = task->ccs_flags;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
	const u8 acc_mode = (flag & 3) == 3 ? 0 : ACC_MODE(flag);
#else
	const u8 acc_mode = (ccs_flags & CCS_OPEN_FOR_IOCTL_ONLY) ? 0 :
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 14)
		(ccs_flags & CCS_OPEN_FOR_READ_TRUNCATE) ? 4 :
#endif
		ACC_MODE(flag);
#endif
	int error = 0;
	struct ccs_path_info buf;
	int idx;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
	if (task->in_execve && !(ccs_flags & CCS_TASK_IS_IN_EXECVE))
		return 0;
#endif
	if (!mnt || (dentry->d_inode && S_ISDIR(dentry->d_inode->i_mode)))
		return 0;
	buf.name = NULL;
	r.mode = CCS_CONFIG_DISABLED;
	idx = ccs_read_lock();
	/*
	 * If the filename is specified by "deny_rewrite" keyword,
	 * we need to check "allow_rewrite" permission when the filename is not
	 * opened for append mode or the filename is truncated at open time.
	 */
	if ((acc_mode & MAY_WRITE) && !(flag & O_APPEND)
	    && ccs_init_request_info(&r, CCS_MAC_FILE_REWRITE)
	    != CCS_CONFIG_DISABLED) {
		if (!ccs_get_realpath(&buf, dentry, mnt)) {
			error = -ENOMEM;
			goto out;
		}
		if (ccs_is_no_rewrite_file(&buf)) {
			r.obj = &obj;
			error = ccs_path_permission(&r, CCS_TYPE_REWRITE,
						    &buf);
		}
	}
	if (!error && acc_mode &&
	    ccs_init_request_info(&r, CCS_MAC_FILE_OPEN)
	    != CCS_CONFIG_DISABLED) {
		if (!buf.name && !ccs_get_realpath(&buf, dentry, mnt)) {
			error = -ENOMEM;
			goto out;
		}
		r.obj = &obj;
		error = ccs_file_perm(&r, &buf, acc_mode);
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
	if (!error && (flag & O_TRUNC) &&
	    ccs_init_request_info(&r, CCS_MAC_FILE_TRUNCATE)
	    != CCS_CONFIG_DISABLED) {
		if (!buf.name && !ccs_get_realpath(&buf, dentry, mnt)) {
			error = -ENOMEM;
			goto out;
		}
		r.obj = &obj;
		error = ccs_path_permission(&r, CCS_TYPE_TRUNCATE, &buf);
	}
#endif
 out:
	kfree(buf.name);
	ccs_read_unlock(idx);
	if (r.mode != CCS_CONFIG_ENFORCING)
		error = 0;
	return error;
}

/**
 * ccs_path_perm - Check permission for "unlink", "rmdir", "truncate", "symlink", "chroot" and "unmount".
 *
 * @operation: Type of operation.
 * @dir:       Pointer to "struct inode". May be NULL.
 * @dentry:    Pointer to "struct dentry".
 * @mnt:       Pointer to "struct vfsmount".
 * @target:    Symlink's target if @operation is CCS_TYPE_SYMLINK.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path_perm(const u8 operation, struct inode *dir,
			 struct dentry *dentry, struct vfsmount *mnt,
			 const char *target)
{
	struct ccs_request_info r;
	struct ccs_obj_info obj = {
		.path1.dentry = dentry,
		.path1.mnt = mnt
	};
	int error = 0;
	struct ccs_path_info buf;
	bool is_enforce = false;
	struct ccs_path_info symlink_target;
	int idx;
	if (!mnt)
		return 0;
	buf.name = NULL;
	symlink_target.name = NULL;
	idx = ccs_read_lock();
	if (ccs_init_request_info(&r, ccs_p2mac[operation])
	    == CCS_CONFIG_DISABLED)
		goto out;
	is_enforce = (r.mode == CCS_CONFIG_ENFORCING);
	error = -ENOMEM;
	if (!ccs_get_realpath(&buf, dentry, mnt))
		goto out;
	r.obj = &obj;
	switch (operation) {
	case CCS_TYPE_RMDIR:
	case CCS_TYPE_CHROOT:
		ccs_add_slash(&buf);
		break;
	case CCS_TYPE_SYMLINK:
		symlink_target.name = ccs_encode(target);
		if (!symlink_target.name)
			goto out;
		ccs_fill_path_info(&symlink_target);
		obj.symlink_target = &symlink_target;
		break;
	}
	error = ccs_path_permission(&r, operation, &buf);
	if (operation == CCS_TYPE_SYMLINK)
		kfree(symlink_target.name);
 out:
	kfree(buf.name);
	ccs_read_unlock(idx);
	if (!is_enforce)
		error = 0;
	return error;
}

/**
 * ccs_path_number3_perm - Check permission for "mkblock" and "mkchar".
 *
 * @operation: Type of operation. (CCS_TYPE_MKCHAR or CCS_TYPE_MKBLOCK)
 * @dir:       Pointer to "struct inode".
 * @dentry:    Pointer to "struct dentry".
 * @mnt:       Pointer to "struct vfsmount".
 * @mode:      Create mode.
 * @dev:       Device number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path_number3_perm(const u8 operation, struct inode *dir,
				 struct dentry *dentry, struct vfsmount *mnt,
				 const unsigned int mode, unsigned int dev)
{
	struct ccs_request_info r;
	struct ccs_obj_info obj = {
		.path1.dentry = dentry,
		.path1.mnt = mnt,
		.dev = dev
	};
	int error = 0;
	struct ccs_path_info buf;
	bool is_enforce = false;
	int idx;
	if (!mnt)
		return 0;
	buf.name = NULL;
	idx = ccs_read_lock();
	if (ccs_init_request_info(&r, ccs_pnnn2mac[operation])
	    == CCS_CONFIG_DISABLED)
		goto out;
	is_enforce = (r.mode == CCS_CONFIG_ENFORCING);
	error = -EPERM;
	if (!capable(CAP_MKNOD))
		goto out;
	error = -ENOMEM;
	if (!ccs_get_realpath(&buf, dentry, mnt))
		goto out;
	r.obj = &obj;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
	dev = new_decode_dev(dev);
#endif
	error = ccs_path_number3_perm2(&r, operation, &buf, mode, dev);
 out:
	kfree(buf.name);
	ccs_read_unlock(idx);
	if (!is_enforce)
		error = 0;
	return error;
}

/**
 * ccs_rewrite_permission - Check permission for "rewrite".
 *
 * @filp: Pointer to "struct file".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_rewrite_permission(struct file *filp)
{
	struct ccs_request_info r;
	struct ccs_obj_info obj = {
		.path1.dentry = filp->f_dentry,
		.path1.mnt = filp->f_vfsmnt
	};
	int error = 0;
	bool is_enforce = false;
	struct ccs_path_info buf;
	int idx;
	if (!filp->f_vfsmnt)
		return 0;
	buf.name = NULL;
	idx = ccs_read_lock();
	if (ccs_init_request_info(&r, CCS_MAC_FILE_REWRITE)
	    == CCS_CONFIG_DISABLED)
		goto out;
	is_enforce = (r.mode == CCS_CONFIG_ENFORCING);
	r.obj = &obj;
	error = -ENOMEM;
	if (!ccs_get_realpath(&buf, filp->f_dentry, filp->f_vfsmnt))
		goto out;
	error = 0;
	if (ccs_is_no_rewrite_file(&buf))
		error = ccs_path_permission(&r, CCS_TYPE_REWRITE, &buf);
 out:
	kfree(buf.name);
	ccs_read_unlock(idx);
	if (!is_enforce)
		error = 0;
	return error;
}

/**
 * ccs_path2_perm - Check permission for "rename", "link" and "pivot_root".
 *
 * @operation: Type of operation.
 * @dir1:      Pointer to "struct inode". May be NULL.
 * @dentry1:   Pointer to "struct dentry".
 * @mnt1:      Pointer to "struct vfsmount".
 * @dir2:      Pointer to "struct inode". May be NULL.
 * @dentry2:   Pointer to "struct dentry".
 * @mnt2:      Pointer to "struct vfsmount".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path2_perm(const u8 operation, struct inode *dir1,
			  struct dentry *dentry1, struct vfsmount *mnt1,
			  struct inode *dir2, struct dentry *dentry2,
			  struct vfsmount *mnt2)
{
	struct ccs_request_info r;
	int error = 0;
	const char *msg = ccs_path22keyword(operation);
	struct ccs_path_info buf1;
	struct ccs_path_info buf2;
	bool is_enforce = false;
	struct ccs_obj_info obj = {
		.path1.dentry = dentry1,
		.path1.mnt = mnt1,
		.path2.dentry = dentry2,
		.path2.mnt = mnt2
	};
	int idx;
	if (!mnt1 || !mnt2)
		return 0;
	buf1.name = NULL;
	buf2.name = NULL;
	idx = ccs_read_lock();
	if (ccs_init_request_info(&r, ccs_pp2mac[operation])
	    == CCS_CONFIG_DISABLED)
		goto out;
	is_enforce = (r.mode == CCS_CONFIG_ENFORCING);
	error = -ENOMEM;
	if (!ccs_get_realpath(&buf1, dentry1, mnt1) ||
	    !ccs_get_realpath(&buf2, dentry2, mnt2))
		goto out;
	switch (operation) {
	case CCS_TYPE_RENAME:
	case CCS_TYPE_LINK:
		if (!dentry1->d_inode || !S_ISDIR(dentry1->d_inode->i_mode))
			break;
		/* fall through */
	case CCS_TYPE_PIVOT_ROOT:
		ccs_add_slash(&buf1);
		ccs_add_slash(&buf2);
		break;
	}
	r.obj = &obj;
	do {
		error = ccs_path2_acl(&r, operation, &buf1, &buf2);
		ccs_audit_path2_log(&r, msg, buf1.name, buf2.name, !error);
		if (!error)
			break;
		error = ccs_supervisor(&r, "allow_%s %s %s\n", msg,
				       ccs_file_pattern(&buf1),
				       ccs_file_pattern(&buf2));
	} while (error == CCS_RETRY_REQUEST);
 out:
	kfree(buf1.name);
	kfree(buf2.name);
	ccs_read_unlock(idx);
	if (!is_enforce)
		error = 0;
	return error;
}

/**
 * ccs_update_path_number_acl - Update ioctl/chmod/chown/chgrp ACL.
 *
 * @type:      Type of operation.
 * @filename:  Filename.
 * @number:    Number.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static inline int ccs_update_path_number_acl(const u8 type,
					     const char *filename,
					     char *number,
					     struct ccs_domain_info * const
					     domain,
					     struct ccs_condition *condition,
					     const bool is_delete)
{
	const u8 perm = 1 << type;
	struct ccs_acl_info *ptr;
	struct ccs_path_number_acl e = {
		.head.type = CCS_TYPE_PATH_NUMBER_ACL,
		.head.cond = condition,
		.perm = perm
	};
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!domain)
		return -EINVAL;
	if (!ccs_parse_name_union(filename, &e.name))
		return -EINVAL;
	if (!ccs_parse_number_union(number, &e.number))
		goto out;
	if (mutex_lock_interruptible(&ccs_policy_lock))
		goto out;
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_path_number_acl *acl =
			container_of(ptr, struct ccs_path_number_acl, head);
		if (!ccs_is_same_path_number_acl(acl, &e))
			continue;
		if (is_delete) {
			acl->perm &= ~perm;
			if (!acl->perm)
				ptr->is_deleted = true;
		} else {
			if (ptr->is_deleted)
				acl->perm = 0;
			acl->perm |= perm;
			ptr->is_deleted = false;
		}
		error = 0;
		break;
	}
	if (!is_delete && error) {
		struct ccs_path_number_acl *entry =
			ccs_commit_ok(&e, sizeof(e));
		if (entry) {
			ccs_add_domain_acl(domain, &entry->head);
			error = 0;
		}
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name_union(&e.name);
	ccs_put_number_union(&e.number);
	return error;
}

/**
 * ccs_path_number_acl - Check permission for ioctl/chmod/chown/chgrp operation.
 *
 * @r:        Pointer to "struct ccs_request_info".
 * @type:     Operation.
 * @filename: Filename to check.
 * @number:   Number.
 *
 * Returns 0 on success, -EPERM otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_path_number_acl(struct ccs_request_info *r, const u8 type,
			       const struct ccs_path_info *filename,
			       const unsigned long number)
{
	const struct ccs_domain_info * const domain = ccs_current_domain();
	struct ccs_acl_info *ptr;
	const u8 perm = 1 << type;
	int error = -EPERM;
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_path_number_acl *acl;
		if (ptr->is_deleted || ptr->type != CCS_TYPE_PATH_NUMBER_ACL)
			continue;
		acl = container_of(ptr, struct ccs_path_number_acl, head);
		if (!(acl->perm & perm) || !ccs_condition(r, ptr) ||
		    !ccs_compare_number_union(number, &acl->number) ||
		    !ccs_compare_name_union(filename, &acl->name))
			continue;
		r->cond = ptr->cond;
		error = 0;
		break;
	}
	return error;
}

/**
 * ccs_path_number_perm2 - Check permission for "create", "mkdir", "mkfifo", "mksock", "ioctl", "chmod", "chown", "chgrp".
 *
 * @r:        Pointer to "struct ccs_request_info".
 * @filename: Filename to check.
 * @number:   Number.
 *
 * Returns 0 on success, 1 on retry, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_path_number_perm2(struct ccs_request_info *r, const u8 type,
				 const struct ccs_path_info *filename,
				 const unsigned long number)
{
	char buffer[64];
	int error;
	u8 radix;
	const char *msg = ccs_path_number2keyword(type);
	if (!filename)
		return 0;
	switch (type) {
	case CCS_TYPE_CREATE:
	case CCS_TYPE_MKDIR:
	case CCS_TYPE_MKFIFO:
	case CCS_TYPE_MKSOCK:
	case CCS_TYPE_CHMOD:
		radix = CCS_VALUE_TYPE_OCTAL;
		break;
	case CCS_TYPE_IOCTL:
		radix = CCS_VALUE_TYPE_HEXADECIMAL;
		break;
	default:
		radix = CCS_VALUE_TYPE_DECIMAL;
		break;
	}
	ccs_print_ulong(buffer, sizeof(buffer), number, radix);
	do {
		error = ccs_path_number_acl(r, type, filename, number);
		ccs_audit_path_number_log(r, msg, filename->name, buffer,
					  !error);
		if (!error)
			return 0;
		error = ccs_supervisor(r, "allow_%s %s %s\n", msg,
				       ccs_file_pattern(filename), buffer);
	} while (error == CCS_RETRY_REQUEST);
	if (r->mode != CCS_CONFIG_ENFORCING)
		error = 0;
	return error;
}

/**
 * ccs_path_number_perm - Check permission for "create", "mkdir", "mkfifo", "mksock", "ioctl", "chmod", "chown", "chgrp".
 *
 * @type:   Type of operation.
 * @dir:    Pointer to "struct inode". May be NULL.
 * @dentry: Pointer to "struct dentry".
 * @vfsmnt: Pointer to "struct vfsmount".
 * @number: Number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path_number_perm(const u8 type, struct inode *dir,
				struct dentry *dentry, struct vfsmount *vfsmnt,
				unsigned long number)
{
	struct ccs_request_info r;
	struct ccs_obj_info obj = {
		.path1.dentry = dentry,
		.path1.mnt = vfsmnt
	};
	int error = 0;
	struct ccs_path_info buf;
	int idx;
	if (!vfsmnt || !dentry)
		return 0;
	buf.name = NULL;
	idx = ccs_read_lock();
	if (ccs_init_request_info(&r, ccs_pn2mac[type]) == CCS_CONFIG_DISABLED)
		goto out;
	error = -ENOMEM;
	if (!ccs_get_realpath(&buf, dentry, vfsmnt))
		goto out;
	r.obj = &obj;
	if (type == CCS_TYPE_MKDIR)
		ccs_add_slash(&buf);
	error = ccs_path_number_perm2(&r, type, &buf, number);
 out:
	kfree(buf.name);
	ccs_read_unlock(idx);
	if (r.mode != CCS_CONFIG_ENFORCING)
		error = 0;
	return error;
}

/**
 * ccs_ioctl_permission - Check permission for "ioctl".
 *
 * @file: Pointer to "struct file".
 * @cmd:  Ioctl command number.
 * @arg:  Param for @cmd .
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_ioctl_permission(struct file *filp, unsigned int cmd,
				  unsigned long arg)
{
	return ccs_path_number_perm(CCS_TYPE_IOCTL, NULL, filp->f_dentry,
				    filp->f_vfsmnt, cmd);
}

/**
 * ccs_chmod_permission - Check permission for "chmod".
 *
 * @dentry: Pointer to "struct dentry".
 * @vfsmnt: Pointer to "struct vfsmount".
 * @mode:   Mode.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_chmod_permission(struct dentry *dentry,
				  struct vfsmount *vfsmnt, mode_t mode)
{
	if (mode == (mode_t) -1)
		return 0;
	if (!ccs_capable(CCS_SYS_CHMOD))
		return -EPERM;
	return ccs_path_number_perm(CCS_TYPE_CHMOD, NULL, dentry, vfsmnt,
				    mode & S_IALLUGO);
}

/**
 * ccs_chown_permission - Check permission for "chown/chgrp".
 *
 * @dentry: Pointer to "struct dentry".
 * @vfsmnt: Pointer to "struct vfsmount".
 * @user:   User ID.
 * @group:  Group ID.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_chown_permission(struct dentry *dentry,
				  struct vfsmount *vfsmnt, uid_t user,
				  gid_t group)
{
	int error = 0;
	if (user == (uid_t) -1 && group == (gid_t) -1)
		return 0;
	if (!ccs_capable(CCS_SYS_CHOWN))
		return -EPERM;
	if (user != (uid_t) -1)
		error = ccs_path_number_perm(CCS_TYPE_CHOWN, NULL, dentry,
					     vfsmnt, user);
	if (!error && group != (gid_t) -1)
		error = ccs_path_number_perm(CCS_TYPE_CHGRP, NULL, dentry,
					     vfsmnt, group);
	return error;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
static int __ccs_fcntl_permission(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	if (cmd == F_SETFL && ((arg ^ file->f_flags) & O_APPEND) &&
	    __ccs_rewrite_permission(file))
		return -EPERM;
	return 0;
}
#endif

/**
 * ccs_pivot_root_permission - Check permission for pivot_root().
 *
 * @old_path: Pointer to "struct path".
 * @new_path: Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_pivot_root_permission(struct path *old_path,
				       struct path *new_path)
{
	if (!ccs_capable(CCS_SYS_PIVOT_ROOT))
		return -EPERM;
	return ccs_path2_perm(CCS_TYPE_PIVOT_ROOT, NULL, new_path->dentry,
			      new_path->mnt, NULL, old_path->dentry,
			      old_path->mnt);
}

/**
 * ccs_chroot_permission - Check permission for chroot().
 *
 * @path: Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_chroot_permission(struct path *path)
{
	if (!ccs_capable(CCS_SYS_CHROOT))
		return -EPERM;
	return ccs_path_perm(CCS_TYPE_CHROOT, NULL, path->dentry, path->mnt,
			     NULL);
}

/**
 * ccs_umount_permission - Check permission for unmount.
 *
 * @mnt:   Pointer to "struct vfsmount".
 * @flags: Umount flags.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_umount_permission(struct vfsmount *mnt, int flags)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
	if (!ccs_capable(CCS_SYS_UMOUNT))
		return -EPERM;
#endif
	return ccs_path_perm(CCS_TYPE_UMOUNT, NULL, mnt->mnt_root, mnt, NULL);
}

/**
 * ccs_write_file_policy - Update file related list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_file_policy(char *data, struct ccs_domain_info *domain,
			  struct ccs_condition *condition,
			  const bool is_delete)
{
	char *w[5];
	u8 type;
	if (!ccs_tokenize(data, w, sizeof(w)) || !w[1][0])
		return -EINVAL;
	if (strncmp(w[0], "allow_", 6)) {
		unsigned int perm;
		if (sscanf(w[0], "%u", &perm) == 1)
			return ccs_update_file_acl((u8) perm, w[1], domain,
						   condition, is_delete);
		if (!strcmp(w[0], CCS_KEYWORD_EXECUTE_HANDLER))
			type = CCS_TYPE_EXECUTE_HANDLER;
		else if (!strcmp(w[0], CCS_KEYWORD_DENIED_EXECUTE_HANDLER))
			type = CCS_TYPE_DENIED_EXECUTE_HANDLER;
		else
			goto out;
		return ccs_update_execute_handler(type, w[1], domain,
						  is_delete);
	}
	w[0] += 6;
	for (type = 0; type < CCS_MAX_PATH_OPERATION; type++) {
		if (strcmp(w[0], ccs_path_keyword[type]))
			continue;
		return ccs_update_path_acl(type, w[1], domain, condition,
					   is_delete);
	}
	if (!w[2][0])
		goto out;
	for (type = 0; type < CCS_MAX_PATH2_OPERATION; type++) {
		if (strcmp(w[0], ccs_path2_keyword[type]))
			continue;
		return ccs_update_path2_acl(type, w[1], w[2], domain,
					    condition, is_delete);
	}
	for (type = 0; type < CCS_MAX_PATH_NUMBER_OPERATION; type++) {
		if (strcmp(w[0], ccs_path_number_keyword[type]))
			continue;
		return ccs_update_path_number_acl(type, w[1], w[2], domain,
						  condition, is_delete);
	}
	if (!w[3][0] || !w[4][0])
		goto out;
	for (type = 0; type < CCS_MAX_PATH_NUMBER3_OPERATION; type++) {
		if (strcmp(w[0], ccs_path_number3_keyword[type]))
			continue;
		return ccs_update_path_number3_acl(type, w[1], w[2], w[3],
						   w[4], domain, condition,
						   is_delete);
	}
 out:
	return -EINVAL;
}

/*
 * Permission checks from vfs_mknod().
 *
 * This function is exported because
 * vfs_mknod() is called from net/unix/af_unix.c.
 */
static int __ccs_mknod_permission(struct inode *dir, struct dentry *dentry,
				  struct vfsmount *mnt,
				  const unsigned int mode, unsigned int dev)
{
	int error = 0;
	const unsigned int perm = mode & S_IALLUGO;
	switch (mode & S_IFMT) {
	case S_IFCHR:
		if (!ccs_capable(CCS_CREATE_CHAR_DEV))
			error = -EPERM;
		else
			error = ccs_path_number3_perm(CCS_TYPE_MKCHAR, dir,
						      dentry, mnt, perm, dev);
		break;
	case S_IFBLK:
		if (!ccs_capable(CCS_CREATE_BLOCK_DEV))
			error = -EPERM;
		else
			error = ccs_path_number3_perm(CCS_TYPE_MKBLOCK, dir,
						      dentry, mnt, perm, dev);
		break;
	case S_IFIFO:
		if (!ccs_capable(CCS_CREATE_FIFO))
			error = -EPERM;
		else
			error = ccs_path_number_perm(CCS_TYPE_MKFIFO, dir,
						     dentry, mnt, perm);
		break;
	case S_IFSOCK:
		if (!ccs_capable(CCS_CREATE_UNIX_SOCKET))
			error = -EPERM;
		else
			error = ccs_path_number_perm(CCS_TYPE_MKSOCK, dir,
						     dentry, mnt, perm);
		break;
	case 0:
	case S_IFREG:
		error = ccs_path_number_perm(CCS_TYPE_CREATE, dir, dentry, mnt,
					     perm);
		break;
	}
	return error;
}

/* Permission checks for vfs_mkdir(). */
static int __ccs_mkdir_permission(struct inode *dir, struct dentry *dentry,
				  struct vfsmount *mnt, unsigned int mode)
{
	return ccs_path_number_perm(CCS_TYPE_MKDIR, dir, dentry, mnt, mode);
}

/* Permission checks for vfs_rmdir(). */
static int __ccs_rmdir_permission(struct inode *dir, struct dentry *dentry,
				  struct vfsmount *mnt)
{
	return ccs_path_perm(CCS_TYPE_RMDIR, dir, dentry, mnt, NULL);
}

/* Permission checks for vfs_unlink(). */
static int __ccs_unlink_permission(struct inode *dir, struct dentry *dentry,
				   struct vfsmount *mnt)
{
	if (!ccs_capable(CCS_SYS_UNLINK))
		return -EPERM;
	return ccs_path_perm(CCS_TYPE_UNLINK, dir, dentry, mnt, NULL);
}

/* Permission checks for vfs_symlink(). */
static int __ccs_symlink_permission(struct inode *dir, struct dentry *dentry,
				    struct vfsmount *mnt, const char *from)
{
	if (!ccs_capable(CCS_SYS_SYMLINK))
		return -EPERM;
	return ccs_path_perm(CCS_TYPE_SYMLINK, dir, dentry, mnt, from);
}

/* Permission checks for notify_change(). */
static int __ccs_truncate_permission(struct dentry *dentry,
				     struct vfsmount *mnt)
{
	return ccs_path_perm(CCS_TYPE_TRUNCATE, NULL, dentry, mnt, NULL);
}

/* Permission checks for vfs_rename(). */
static int __ccs_rename_permission(struct inode *old_dir,
				   struct dentry *old_dentry,
				   struct inode *new_dir,
				   struct dentry *new_dentry,
				   struct vfsmount *mnt)
{
	if (!ccs_capable(CCS_SYS_RENAME))
		return -EPERM;
	return ccs_path2_perm(CCS_TYPE_RENAME, old_dir, old_dentry, mnt,
			      new_dir, new_dentry, mnt);
}

/* Permission checks for vfs_link(). */
static int __ccs_link_permission(struct dentry *old_dentry,
				 struct inode *new_dir,
				 struct dentry *new_dentry,
				 struct vfsmount *mnt)
{
	if (!ccs_capable(CCS_SYS_LINK))
		return -EPERM;
	return ccs_path2_perm(CCS_TYPE_LINK, NULL, old_dentry, mnt,
			      new_dir, new_dentry, mnt);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
/* Permission checks for open_exec(). */
static int __ccs_open_exec_permission(struct dentry *dentry,
				      struct vfsmount *mnt)
{
	return (current->ccs_flags & CCS_TASK_IS_IN_EXECVE) ?
		/* 01 means "read". */
		ccs_open_permission(dentry, mnt, 01) : 0;
}

/* Permission checks for sys_uselib(). */
static int __ccs_uselib_permission(struct dentry *dentry, struct vfsmount *mnt)
{
	/* 01 means "read". */
	return ccs_open_permission(dentry, mnt, 01);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18) || defined(CONFIG_SYSCTL_SYSCALL)

#include <linux/sysctl.h>

/* Permission checks for parse_table(). */
static int __ccs_parse_table(int __user *name, int nlen, void __user *oldval,
			     void __user *newval, struct ctl_table *table)
{
	int n;
	int error = -ENOMEM;
	int op = 0;
	struct ccs_path_info buf;
	char *buffer = NULL;
	struct ccs_request_info r;
	int idx;
	if (oldval)
		op |= 004;
	if (newval)
		op |= 002;
	if (!op) /* Neither read nor write */
		return 0;
	idx = ccs_read_lock();
	if (ccs_init_request_info(&r, CCS_MAC_FILE_OPEN)
	    == CCS_CONFIG_DISABLED) {
		error = 0;
		goto out;
	}
	buffer = kmalloc(PAGE_SIZE, CCS_GFP_FLAGS);
	if (!buffer)
		goto out;
	snprintf(buffer, PAGE_SIZE - 1, "/proc/sys");
 repeat:
	if (!nlen) {
		error = -ENOTDIR;
		goto out;
	}
	if (get_user(n, name)) {
		error = -EFAULT;
		goto out;
	}
	for ( ; table->ctl_name
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 21)
		      || table->procname
#endif
		      ; table++) {
		int pos;
		const char *cp;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 21)
		if (n != table->ctl_name && table->ctl_name != CTL_ANY)
			continue;
#else
		if (!n || n != table->ctl_name)
			continue;
#endif
		pos = strlen(buffer);
		cp = table->procname;
		error = -ENOMEM;
		if (cp) {
			int len = strlen(cp);
			if (len + 2 > PAGE_SIZE - 1)
				goto out;
			buffer[pos++] = '/';
			memmove(buffer + pos, cp, len + 1);
		} else {
			/* Assume nobody assigns "=\$=" for procname. */
			snprintf(buffer + pos, PAGE_SIZE - pos - 1,
				 "/=%d=", table->ctl_name);
			if (!memchr(buffer, '\0', PAGE_SIZE - 2))
				goto out;
		}
		if (table->child) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 21)
			if (table->strategy) {
				/* printk("sysctl='%s'\n", buffer); */
				buf.name = ccs_encode(buffer);
				if (buf.name) {
					ccs_fill_path_info(&buf);
					error = ccs_file_perm(&r, &buf, op);
					kfree(buf.name);
				}
				if (error)
					goto out;
			}
#endif
			name++;
			nlen--;
			table = table->child;
			goto repeat;
		}
		/* printk("sysctl='%s'\n", buffer); */
		buf.name = ccs_encode(buffer);
		if (buf.name) {
			ccs_fill_path_info(&buf);
			error = ccs_file_perm(&r, &buf, op);
			kfree(buf.name);
		}
		goto out;
	}
	error = -ENOTDIR;
 out:
	ccs_read_unlock(idx);
	kfree(buffer);
	return error;
}
#endif
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 24)
static int ccs_old_pivot_root_permission(struct nameidata *old_nd,
					 struct nameidata *new_nd)
{
	struct path old_path = { old_nd->mnt, old_nd->dentry };
	struct path new_path = { new_nd->mnt, new_nd->dentry };
	return __ccs_pivot_root_permission(&old_path, &new_path);
}

static int ccs_old_chroot_permission(struct nameidata *nd)
{
	struct path path = { nd->mnt, nd->dentry };
	return __ccs_chroot_permission(&path);
}
#endif

void __init ccs_file_init(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 34)
	ccsecurity_ops.save_open_mode = __ccs_save_open_mode;
	ccsecurity_ops.clear_open_mode = __ccs_clear_open_mode;
#endif
	ccsecurity_ops.open_permission = __ccs_open_permission;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
	ccsecurity_ops.fcntl_permission = __ccs_fcntl_permission;
#else
	ccsecurity_ops.rewrite_permission = __ccs_rewrite_permission;
#endif
	ccsecurity_ops.ioctl_permission = __ccs_ioctl_permission;
	ccsecurity_ops.chmod_permission = __ccs_chmod_permission;
	ccsecurity_ops.chown_permission = __ccs_chown_permission;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	ccsecurity_ops.pivot_root_permission = __ccs_pivot_root_permission;
	ccsecurity_ops.chroot_permission = __ccs_chroot_permission;
#else
	ccsecurity_ops.pivot_root_permission = ccs_old_pivot_root_permission;
	ccsecurity_ops.chroot_permission = ccs_old_chroot_permission;
#endif
	ccsecurity_ops.umount_permission = __ccs_umount_permission;
	ccsecurity_ops.mknod_permission = __ccs_mknod_permission;
	ccsecurity_ops.mkdir_permission = __ccs_mkdir_permission;
	ccsecurity_ops.rmdir_permission = __ccs_rmdir_permission;
	ccsecurity_ops.unlink_permission = __ccs_unlink_permission;
	ccsecurity_ops.symlink_permission = __ccs_symlink_permission;
	ccsecurity_ops.truncate_permission = __ccs_truncate_permission;
	ccsecurity_ops.rename_permission = __ccs_rename_permission;
	ccsecurity_ops.link_permission = __ccs_link_permission;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	ccsecurity_ops.open_exec_permission = __ccs_open_exec_permission;
	ccsecurity_ops.uselib_permission = __ccs_uselib_permission;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18) || defined(CONFIG_SYSCTL_SYSCALL)
	ccsecurity_ops.parse_table = __ccs_parse_table;
#endif
#endif
};
