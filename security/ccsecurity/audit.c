/*
 * security/ccsecurity/audit.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.7.2+   2011/01/21
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/slab.h>
#include "internal.h"

/**
 * ccs_print_bprm - Print "struct linux_binprm" for auditing.
 *
 * @bprm: Pointer to "struct linux_binprm".
 * @dump: Pointer to "struct ccs_page_dump".
 *
 * Returns the contents of @bprm on success, NULL otherwise.
 *
 * This function uses kzalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
static char *ccs_print_bprm(struct linux_binprm *bprm,
			    struct ccs_page_dump *dump)
{
	static const int ccs_buffer_len = 4096 * 2;
	char *buffer = kzalloc(ccs_buffer_len, CCS_GFP_FLAGS);
	char *cp;
	char *last_start;
	int len;
	unsigned long pos = bprm->p;
	int offset = pos % PAGE_SIZE;
	int argv_count = bprm->argc;
	int envp_count = bprm->envc;
	bool truncated = false;
	if (!buffer)
		return NULL;
	len = snprintf(buffer, ccs_buffer_len - 1, "argv[]={ ");
	cp = buffer + len;
	if (!argv_count) {
		memmove(cp, "} envp[]={ ", 11);
		cp += 11;
	}
	last_start = cp;
	while (argv_count || envp_count) {
		if (!ccs_dump_page(bprm, pos, dump))
			goto out;
		pos += PAGE_SIZE - offset;
		/* Read. */
		while (offset < PAGE_SIZE) {
			const char *kaddr = dump->data;
			const unsigned char c = kaddr[offset++];
			if (cp == last_start)
				*cp++ = '"';
			if (cp >= buffer + ccs_buffer_len - 32) {
				/* Reserve some room for "..." string. */
				truncated = true;
			} else if (c == '\\') {
				*cp++ = '\\';
				*cp++ = '\\';
			} else if (c > ' ' && c < 127) {
				*cp++ = c;
			} else if (!c) {
				*cp++ = '"';
				*cp++ = ' ';
				last_start = cp;
			} else {
				*cp++ = '\\';
				*cp++ = (c >> 6) + '0';
				*cp++ = ((c >> 3) & 7) + '0';
				*cp++ = (c & 7) + '0';
			}
			if (c)
				continue;
			if (argv_count) {
				if (--argv_count == 0) {
					if (truncated) {
						cp = last_start;
						memmove(cp, "... ", 4);
						cp += 4;
					}
					memmove(cp, "} envp[]={ ", 11);
					cp += 11;
					last_start = cp;
					truncated = false;
				}
			} else if (envp_count) {
				if (--envp_count == 0) {
					if (truncated) {
						cp = last_start;
						memmove(cp, "... ", 4);
						cp += 4;
					}
				}
			}
			if (!argv_count && !envp_count)
				break;
		}
		offset = 0;
	}
	*cp++ = '}';
	*cp = '\0';
	return buffer;
 out:
	snprintf(buffer, ccs_buffer_len - 1, "argv[]={ ... } envp[]= { ... }");
	return buffer;
}

/**
 * ccs_filetype - Get string representation of file type.
 *
 * @mode: Mode value for stat().
 *
 * Returns file type string.
 */
static const char *ccs_filetype(const mode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFREG:
	case 0:
		return "file";
	case S_IFDIR:
		return "directory";
	case S_IFLNK:
		return "symlink";
	case S_IFIFO:
		return "fifo";
	case S_IFSOCK:
		return "socket";
	case S_IFBLK:
		return "block";
	case S_IFCHR:
		return "char";
	}
	return "unknown"; /* This should not happen. */
}

/**
 * ccs_print_header - Get header line of audit log.
 *
 * @r: Pointer to "struct ccs_request_info".
 *
 * Returns string representation.
 *
 * This function uses kmalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
static char *ccs_print_header(struct ccs_request_info *r)
{
	static const char *ccs_mode_4[4] = {
		"disabled", "learning", "permissive", "enforcing"
	};
	struct timeval tv;
	unsigned int dev;
	mode_t mode;
	struct ccs_obj_info *obj = r->obj;
	const u32 ccs_flags = current->ccs_flags;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
	const pid_t gpid = (pid_t) ccsecurity_exports.sys_getpid();
#else
	const pid_t gpid = task_pid_nr(current);
#endif
	static const int ccs_buffer_len = 4096;
	char *buffer = kmalloc(ccs_buffer_len, CCS_GFP_FLAGS);
	int pos;
	if (!buffer)
		return NULL;
	do_gettimeofday(&tv);
	pos = snprintf(buffer, ccs_buffer_len - 1,
		       "#timestamp=%lu profile=%u mode=%s "
		       "(global-pid=%u)", tv.tv_sec, r->profile,
		       ccs_mode_4[r->mode], gpid);
	if (ccs_profile(r->profile)->audit->audit_task_info) {
		pos += snprintf(buffer + pos, ccs_buffer_len - 1 - pos,
				" task={ pid=%u ppid=%u uid=%u gid=%u euid=%u"
				" egid=%u suid=%u sgid=%u fsuid=%u fsgid=%u"
				" state[0]=%u state[1]=%u state[2]=%u"
				" type%s=execute_handler }",
				(pid_t) ccsecurity_exports.sys_getpid(),
				(pid_t) ccsecurity_exports.sys_getppid(),
				current_uid(), current_gid(), current_euid(),
				current_egid(), current_suid(), current_sgid(),
				current_fsuid(), current_fsgid(),
				(u8) (ccs_flags >> 24), (u8) (ccs_flags >> 16),
				(u8) (ccs_flags >> 8), ccs_flags &
				CCS_TASK_IS_EXECUTE_HANDLER ? "" : "!");
	}
	if (!obj || !ccs_profile(r->profile)->audit->audit_path_info)
		goto no_obj_info;
	if (!obj->validate_done) {
		ccs_get_attributes(obj);
		obj->validate_done = true;
	}
	if (obj->path1_valid) {
		dev = obj->path1_stat.dev;
		mode = obj->path1_stat.mode;
		pos += snprintf(buffer + pos, ccs_buffer_len - 1 - pos,
				" path1={ uid=%u gid=%u ino=%lu major=%u"
				" minor=%u perm=0%o type=%s",
				obj->path1_stat.uid, obj->path1_stat.gid,
				(unsigned long) obj->path1_stat.ino,
				MAJOR(dev), MINOR(dev), mode & S_IALLUGO,
				ccs_filetype(mode));
		if (S_ISCHR(mode) || S_ISBLK(mode)) {
			dev = obj->path1_stat.rdev;
			pos += snprintf(buffer + pos, ccs_buffer_len - 1 - pos,
					" dev_major=%u dev_minor=%u",
					MAJOR(dev), MINOR(dev));
		}
		pos += snprintf(buffer + pos, ccs_buffer_len - 1 - pos, " }");
	}
	if (obj->path1_parent_valid) {
		pos += snprintf(buffer + pos, ccs_buffer_len - 1 - pos,
				" path1.parent={ uid=%u gid=%u ino=%lu"
				" perm=0%o }", obj->path1_parent_stat.uid,
				obj->path1_parent_stat.gid,
				(unsigned long) obj->path1_parent_stat.ino,
				obj->path1_parent_stat.mode & S_IALLUGO);
	}
	if (obj->path2_valid) {
		dev = obj->path2_stat.dev;
		mode = obj->path2_stat.mode;
		pos += snprintf(buffer + pos, ccs_buffer_len - 1 - pos,
				" path2={ uid=%u gid=%u ino=%lu major=%u"
				" minor=%u perm=0%o type=%s",
				obj->path2_stat.uid, obj->path2_stat.gid,
				(unsigned long) obj->path2_stat.ino,
				MAJOR(dev), MINOR(dev), mode & S_IALLUGO,
				ccs_filetype(mode));
		if (S_ISCHR(mode) || S_ISBLK(mode)) {
			dev = obj->path2_stat.rdev;
			pos += snprintf(buffer + pos, ccs_buffer_len - 1 - pos,
					" dev_major=%u dev_minor=%u",
					MAJOR(dev), MINOR(dev));
		}
		pos += snprintf(buffer + pos, ccs_buffer_len - 1 - pos, " }");
	}
	if (obj->path2_parent_valid) {
		pos += snprintf(buffer + pos, ccs_buffer_len - 1 - pos,
				" path2.parent={ uid=%u gid=%u ino=%lu"
				" perm=0%o }", obj->path2_parent_stat.uid,
				obj->path2_parent_stat.gid,
				(unsigned long) obj->path2_parent_stat.ino,
				obj->path2_parent_stat.mode & S_IALLUGO);
	}
 no_obj_info:
	if (pos < ccs_buffer_len - 1)
		return buffer;
	kfree(buffer);
	return NULL;
}

/**
 * ccs_init_audit_log - Allocate buffer for audit logs.
 *
 * @len: Required size.
 * @r:   Pointer to "struct ccs_request_info".
 *
 * Returns pointer to allocated memory.
 *
 * The @len is updated to add the header lines' size on success.
 *
 * This function uses kzalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
char *ccs_init_audit_log(int *len, struct ccs_request_info *r)
{
	char *buf = NULL;
	char *bprm_info = NULL;
	char *realpath = NULL;
	const char *symlink = NULL;
	const char *header = NULL;
	int pos;
	const char *domainname = ccs_current_domain()->domainname->name;
	header = ccs_print_header(r);
	if (!header)
		return NULL;
	*len += strlen(domainname) + strlen(header) + 10;
	if (r->ee) {
		struct file *file = r->ee->bprm->file;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
		struct path path = { file->f_vfsmnt, file->f_dentry };
		realpath = ccs_realpath_from_path(&path);
#else
		realpath = ccs_realpath_from_path(&file->f_path);
#endif
		bprm_info = ccs_print_bprm(r->ee->bprm, &r->ee->dump);
		if (!realpath || !bprm_info)
			goto out;
		*len += strlen(realpath) + 80 + strlen(bprm_info);
	} else if (r->obj && r->obj->symlink_target) {
		symlink = r->obj->symlink_target->name;
		*len += 18 + strlen(symlink);
	}
	buf = kzalloc(*len, CCS_GFP_FLAGS);
	if (!buf)
		goto out;
	pos = snprintf(buf, (*len) - 1, "%s", header);
	if (realpath) {
		struct linux_binprm *bprm = r->ee->bprm;
		pos += snprintf(buf + pos, (*len) - 1 - pos,
				" exec={ realpath=\"%s\" argc=%d envc=%d %s }",
				realpath, bprm->argc, bprm->envc, bprm_info);
	} else if (symlink)
		pos += snprintf(buf + pos, (*len) - 1 - pos,
				" symlink.target=\"%s\"", symlink);
	snprintf(buf + pos, (*len) - 1 - pos, "\n%s\n", domainname);
 out:
	kfree(realpath);
	kfree(bprm_info);
	kfree(header);
	return buf;
}

/**
 * ccs_update_task_state - Update task's state.
 *
 * @r: Pointer to "struct ccs_request_info".
 */
static void ccs_update_task_state(struct ccs_request_info *r)
{
	/*
	 * Don't change the lowest byte because it is reserved for
	 * CCS_TASK_IS_IN_EXECVE / CCS_DONT_SLEEP_ON_ENFORCE_ERROR /
	 * CCS_TASK_IS_EXECUTE_HANDLER / CCS_TASK_IS_POLICY_MANAGER.
	 */
	const struct ccs_condition *ptr = r->cond;
	if (ptr) {
		struct task_struct *task = current;
		const u8 flags = ptr->post_state[3];
		u32 ccs_flags = task->ccs_flags;
		if (flags & 1) {
			ccs_flags &= ~0xFF000000;
			ccs_flags |= ptr->post_state[0] << 24;
		}
		if (flags & 2) {
			ccs_flags &= ~0x00FF0000;
			ccs_flags |= ptr->post_state[1] << 16;
		}
		if (flags & 4) {
			ccs_flags &= ~0x0000FF00;
			ccs_flags |= ptr->post_state[2] << 8;
		}
		task->ccs_flags = ccs_flags;
		r->cond = NULL;
	}
}

#ifndef CONFIG_CCSECURITY_AUDIT

/**
 * ccs_write_audit_log - Write audit log.
 *
 * @is_granted: True if this is a granted log.
 * @r:          Pointer to "struct ccs_request_info".
 * @fmt:        The printf()'s format string, followed by parameters.
 *
 * Returns 0 on success, -ENOMEM otherwise.
 */
int ccs_write_audit_log(const bool is_granted, struct ccs_request_info *r,
			const char *fmt, ...)
{
	ccs_update_task_state(r);
	return 0;
}

#else

static wait_queue_head_t ccs_audit_log_wait[2] = {
	__WAIT_QUEUE_HEAD_INITIALIZER(ccs_audit_log_wait[0]),
	__WAIT_QUEUE_HEAD_INITIALIZER(ccs_audit_log_wait[1]),
};

static DEFINE_SPINLOCK(ccs_audit_log_lock);

/* Structure for audit log. */
struct ccs_audit_log_entry {
	struct list_head list;
	char *log;
	int size;
};

/* The list for "struct ccs_audit_log_entry". */
static struct list_head ccs_audit_log[2] = {
	LIST_HEAD_INIT(ccs_audit_log[0]),
	LIST_HEAD_INIT(ccs_audit_log[1]),
};

static unsigned int ccs_audit_log_count[2];

/**
 * ccs_write_audit_log - Write audit log.
 *
 * @is_granted: True if this is a granted log.
 * @r:          Pointer to "struct ccs_request_info".
 * @fmt:        The printf()'s format string, followed by parameters.
 *
 * Returns 0 on success, -ENOMEM otherwise.
 */
int ccs_write_audit_log(const bool is_granted, struct ccs_request_info *r,
			const char *fmt, ...)
{
	va_list args;
	int error = -ENOMEM;
	int pos;
	int len;
	char *buf;
	struct ccs_audit_log_entry *new_entry;
	bool quota_exceeded = false;
	struct ccs_preference *pref =
		ccs_profile(ccs_current_domain()->profile)->audit;
	if (is_granted)
		len = pref->audit_max_grant_log;
	else
		len = pref->audit_max_reject_log;
	if (ccs_audit_log_count[is_granted] >= len ||
	    !ccs_get_audit(r->profile, r->type, is_granted))
		goto out;
	va_start(args, fmt);
	len = vsnprintf((char *) &pos, sizeof(pos) - 1, fmt, args) + 32;
	va_end(args);
	buf = ccs_init_audit_log(&len, r);
	if (!buf)
		goto out;
	pos = strlen(buf);
	va_start(args, fmt);
	vsnprintf(buf + pos, len - pos - 1, fmt, args);
	va_end(args);
	new_entry = kzalloc(sizeof(*new_entry), CCS_GFP_FLAGS);
	if (!new_entry) {
		kfree(buf);
		goto out;
	}
	new_entry->log = buf;
	/*
	 * The new_entry->size is used for memory quota checks.
	 * Don't go beyond strlen(new_entry->log).
	 */
	new_entry->size = ccs_round2(len) + ccs_round2(sizeof(*new_entry));
	spin_lock(&ccs_audit_log_lock);
	if (ccs_quota_for_audit_log && ccs_audit_log_memory_size
	    + new_entry->size >= ccs_quota_for_audit_log) {
		quota_exceeded = true;
	} else {
		ccs_audit_log_memory_size += new_entry->size;
		list_add_tail(&new_entry->list, &ccs_audit_log[is_granted]);
		ccs_audit_log_count[is_granted]++;
	}
	spin_unlock(&ccs_audit_log_lock);
	if (quota_exceeded) {
		kfree(buf);
		kfree(new_entry);
		goto out;
	}
	wake_up(&ccs_audit_log_wait[is_granted]);
	error = 0;
 out:
	ccs_update_task_state(r);
	return error;
}

/**
 * ccs_read_audit_log - Read an audit log.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 */
void ccs_read_audit_log(struct ccs_io_buffer *head)
{
	struct ccs_audit_log_entry *ptr = NULL;
	const bool is_granted = head->type == CCS_GRANTLOG;
	if (head->read_avail)
		return;
	if (head->read_buf) {
		kfree(head->read_buf);
		head->read_buf = NULL;
		head->readbuf_size = 0;
	}
	spin_lock(&ccs_audit_log_lock);
	if (!list_empty(&ccs_audit_log[is_granted])) {
		ptr = list_entry(ccs_audit_log[is_granted].next,
				 struct ccs_audit_log_entry, list);
		list_del(&ptr->list);
		ccs_audit_log_count[is_granted]--;
		ccs_audit_log_memory_size -= ptr->size;
	}
	spin_unlock(&ccs_audit_log_lock);
	if (ptr) {
		head->read_buf = ptr->log;
		head->read_avail = strlen(ptr->log) + 1;
		head->readbuf_size = head->read_avail;
		kfree(ptr);
	}
}

/**
 * ccs_poll_audit_log - Wait for an audit log.
 *
 * @file: Pointer to "struct file".
 * @wait: Pointer to "poll_table".
 *
 * Returns POLLIN | POLLRDNORM when ready to read a grant log.
 */
int ccs_poll_audit_log(struct file *file, poll_table *wait)
{
	struct ccs_io_buffer *head = file->private_data;
	const bool is_granted = head->type == CCS_GRANTLOG;
	if (ccs_audit_log_count[is_granted])
		return POLLIN | POLLRDNORM;
	poll_wait(file, &ccs_audit_log_wait[is_granted], wait);
	if (ccs_audit_log_count[is_granted])
		return POLLIN | POLLRDNORM;
	return 0;
}

#endif
