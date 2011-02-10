/*
 * security/ccsecurity/signal.c
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.7.2+   2010/06/04
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include "internal.h"

/* To support PID namespace. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
#define find_task_by_pid ccsecurity_exports.find_task_by_vpid
#endif

/**
 * ccs_audit_signal_log - Audit signal log.
 *
 * @r:           Pointer to "struct ccs_request_info".
 * @signal:      Signal number.
 * @dest_domain: Destination domainname.
 * @is_granted:  True if this is a granted log.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_signal_log(struct ccs_request_info *r, const int signal,
				const char *dest_domain, const bool is_granted)
{
	if (!is_granted)
		ccs_warn_log(r, "signal %d to %s", signal,
			     ccs_last_word(dest_domain));
	return ccs_write_audit_log(is_granted, r, CCS_KEYWORD_ALLOW_SIGNAL
				   "%d %s\n", signal, dest_domain);
}

/**
 * ccs_signal_acl2 - Check permission for signal.
 *
 * @sig: Signal number.
 * @pid: Target's PID.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_signal_acl2(const int sig, const int pid)
{
	struct ccs_request_info r;
	struct ccs_domain_info *dest = NULL;
	const char *dest_pattern;
	struct ccs_acl_info *ptr;
	const u16 hash = sig;
	int error;
	const struct ccs_domain_info * const domain = ccs_current_domain();
	if (ccs_init_request_info(&r, CCS_MAC_SIGNAL) == CCS_CONFIG_DISABLED)
		return 0;
	if (!sig)
		return 0;                /* No check for NULL signal. */
	if (ccsecurity_exports.sys_getpid() == pid) {
		ccs_audit_signal_log(&r, sig, domain->domainname->name,
				     true);
		return 0;                /* No check for self process. */
	}
	{ /* Simplified checking. */
		struct task_struct *p = NULL;
		ccs_tasklist_lock();
		if (pid > 0)
			p = find_task_by_pid((pid_t) pid);
		else if (pid == 0)
			p = current;
		else if (pid == -1)
			dest = &ccs_kernel_domain;
		else
			p = find_task_by_pid((pid_t) -pid);
		if (p)
			dest = ccs_task_domain(p);
		ccs_tasklist_unlock();
	}
	if (!dest)
		return 0; /* I can't find destinatioin. */
	if (domain == dest) {
		ccs_audit_signal_log(&r, sig, domain->domainname->name, true);
		return 0;                /* No check for self domain. */
	}
	dest_pattern = dest->domainname->name;
	do {
		error = -EPERM;
		list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
			struct ccs_signal_acl *acl;
			if (ptr->is_deleted ||
			    ptr->type != CCS_TYPE_SIGNAL_ACL)
				continue;
			acl = container_of(ptr, struct ccs_signal_acl, head);
			if (acl->sig == hash && ccs_condition(&r, ptr)) {
				const int len = acl->domainname->total_len;
				if (strncmp(acl->domainname->name,
					    dest_pattern, len))
					continue;
				switch (dest_pattern[len]) {
				case ' ':
				case '\0':
					break;
				default:
					continue;
				}
				r.cond = ptr->cond;
				error = 0;
				break;
			}
		}
		ccs_audit_signal_log(&r, sig, dest_pattern, !error);
		if (!error)
			break;
		error = ccs_supervisor(&r, CCS_KEYWORD_ALLOW_SIGNAL "%d %s\n",
				       sig, dest_pattern);
	} while (error == CCS_RETRY_REQUEST);
	return error;
}

/**
 * ccs_signal_acl - Check permission for signal.
 *
 * @sig: Signal number.
 * @pid: Target's PID.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_signal_acl(const int sig, const int pid)
{
	const int idx = ccs_read_lock();
	const int error = ccs_signal_acl2(sig, pid);
	ccs_read_unlock(idx);
	return error;
}

/**
 * ccs_write_signal_policy - Write "struct ccs_signal_acl" list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_signal_policy(char *data, struct ccs_domain_info *domain,
			    struct ccs_condition *condition,
			    const bool is_delete)
{
	struct ccs_acl_info *ptr;
	struct ccs_signal_acl e = { .head.type = CCS_TYPE_SIGNAL_ACL,
				    .head.cond = condition };
	int error = is_delete ? -ENOENT : -ENOMEM;
	int sig;
	char *domainname = strchr(data, ' ');
	if (sscanf(data, "%d", &sig) != 1 || !domainname ||
	    !ccs_is_correct_domain(domainname + 1))
		return -EINVAL;
	e.sig = sig;
	e.domainname = ccs_get_name(domainname + 1);
	if (!e.domainname)
		return -ENOMEM;
	if (mutex_lock_interruptible(&ccs_policy_lock))
		goto out;
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_signal_acl *acl =
			container_of(ptr, struct ccs_signal_acl, head);
		if (ptr->type != CCS_TYPE_SIGNAL_ACL || ptr->cond != condition
		    || acl->sig != sig || acl->domainname != e.domainname)
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error) {
		struct ccs_signal_acl *entry = ccs_commit_ok(&e, sizeof(e));
		if (entry) {
			ccs_add_domain_acl(domain, &entry->head);
			error = 0;
		}
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name(e.domainname);
	return error;
}

/**
 * ccs_kill_permission - Permission check for kill().
 *
 * @pid: PID
 * @sig: Signal number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_kill_permission(pid_t pid, int sig)
{
	if (sig && (!ccs_capable(CCS_SYS_KILL) ||
		    ccs_signal_acl(sig, pid)))
		return -EPERM;
	return 0;
}

/**
 * ccs_tgkill_permission - Permission check for tgkill().
 *
 * @tgid: TGID
 * @pid:  PID
 * @sig:  Signal number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_tgkill_permission(pid_t tgid, pid_t pid, int sig)
{
	if (sig && (!ccs_capable(CCS_SYS_KILL) ||
		    ccs_signal_acl(sig, pid)))
		return -EPERM;
	return 0;
}

/**
 * ccs_tkill_permission - Permission check for tkill().
 *
 * @pid: PID
 * @sig: Signal number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_tkill_permission(pid_t pid, int sig)
{
	if (sig && (!ccs_capable(CCS_SYS_KILL) ||
		    ccs_signal_acl(sig, pid)))
		return -EPERM;
	return 0;
}

static int __ccs_sigqueue_permission(pid_t pid, int sig)
{
	if (sig && (!ccs_capable(CCS_SYS_KILL) ||
		    ccs_signal_acl(sig, pid)))
		return -EPERM;
	return 0;
}

static int __ccs_tgsigqueue_permission(pid_t tgid, pid_t pid, int sig)
{
	if (sig && (!ccs_capable(CCS_SYS_KILL) ||
		    ccs_signal_acl(sig, pid)))
		return -EPERM;
	return 0;
}

void __init ccs_signal_init(void)
{
	ccsecurity_ops.kill_permission = __ccs_kill_permission;
	ccsecurity_ops.tgkill_permission = __ccs_tgkill_permission;
	ccsecurity_ops.tkill_permission = __ccs_tkill_permission;
	ccsecurity_ops.sigqueue_permission = __ccs_sigqueue_permission;
	ccsecurity_ops.tgsigqueue_permission = __ccs_tgsigqueue_permission;
}
