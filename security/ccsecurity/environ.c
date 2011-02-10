/*
 * security/ccsecurity/environ.c
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

/**
 * ccs_audit_env_log - Audit environment variable name log.
 *
 * @r:          Pointer to "struct ccs_request_info".
 * @env:        The name of environment variable.
 * @is_granted: True if this is a granted log.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_env_log(struct ccs_request_info *r, const char *env,
			     const bool is_granted)
{
	if (!is_granted)
		ccs_warn_log(r, "environ %s", env);
	return ccs_write_audit_log(is_granted, r, CCS_KEYWORD_ALLOW_ENV "%s\n",
				   env);
}

/* The list for "struct ccs_globally_usable_env_entry". */
LIST_HEAD(ccs_globally_usable_env_list);

/**
 * ccs_is_globally_usable_env - Check whether the given environment variable is acceptable for all domains.
 *
 * @env: The name of environment variable.
 *
 * Returns true if @env is globally permitted environment variable's name,
 * false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_is_globally_usable_env(const struct ccs_path_info *env)
{
	struct ccs_globally_usable_env_entry *ptr;
	bool found = false;
	list_for_each_entry_rcu(ptr, &ccs_globally_usable_env_list, list) {
		if (ptr->is_deleted ||
		    !ccs_path_matches_pattern(env, ptr->env))
			continue;
		found = true;
		break;
	}
	return found;
}

/**
 * ccs_write_globally_usable_env_policy - Write "struct ccs_globally_usable_env_entry" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_globally_usable_env_policy(char *data, const bool is_delete)
{
	struct ccs_globally_usable_env_entry e = { };
	struct ccs_globally_usable_env_entry *ptr;
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!ccs_is_correct_path(data, 0, 0, 0) || strchr(data, '='))
		return -EINVAL;
	e.env = ccs_get_name(data);
	if (!e.env)
		return error;
	if (mutex_lock_interruptible(&ccs_policy_lock))
		goto out;
	list_for_each_entry_rcu(ptr, &ccs_globally_usable_env_list, list) {
		if (ptr->env != e.env)
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error) {
		struct ccs_globally_usable_env_entry *entry =
			ccs_commit_ok(&e, sizeof(e));
		if (entry) {
			list_add_tail_rcu(&entry->list,
					  &ccs_globally_usable_env_list);
			error = 0;
		}
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name(e.env);
	return error;
}

/**
 * ccs_read_globally_usable_env_policy - Read "struct ccs_globally_usable_env_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0 on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_read_globally_usable_env_policy(struct ccs_io_buffer *head)
{
	struct list_head *pos;
	bool done = true;
	list_for_each_cookie(pos, head->read_var2,
			     &ccs_globally_usable_env_list) {
		struct ccs_globally_usable_env_entry *ptr;
		ptr = list_entry(pos, struct ccs_globally_usable_env_entry,
				 list);
		if (ptr->is_deleted)
			continue;
		done = ccs_io_printf(head, CCS_KEYWORD_ALLOW_ENV "%s\n",
				     ptr->env->name);
		if (!done)
			break;
	}
	return done;
}

/**
 * ccs_env_acl - Check permission for environment variable's name.
 *
 * @r:       Pointer to "struct ccs_request_info".
 * @environ: The name of environment variable.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_env_acl(struct ccs_request_info *r, const char *environ)
{
	const struct ccs_domain_info * const domain = ccs_current_domain();
	int error = -EPERM;
	struct ccs_acl_info *ptr;
	struct ccs_path_info env;
	env.name = environ;
	ccs_fill_path_info(&env);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_env_acl *acl;
		if (ptr->is_deleted || ptr->type != CCS_TYPE_ENV_ACL)
			continue;
		acl = container_of(ptr, struct ccs_env_acl, head);
		if (!ccs_condition(r, ptr) ||
		    !ccs_path_matches_pattern(&env, acl->env))
			continue;
		r->cond = ptr->cond;
		error = 0;
		break;
	}
	if (error && !domain->ignore_global_allow_env &&
	    ccs_is_globally_usable_env(&env))
		error = 0;
	return error;
}

/**
 * ccs_env_perm - Check permission for environment variable's name.
 *
 * @r:       Pointer to "struct ccs_request_info".
 * @env:     The name of environment variable.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
int ccs_env_perm(struct ccs_request_info *r, const char *env)
{
	int error;
	if (!env || !*env)
		return 0;
	do {
		error = ccs_env_acl(r, env);
		ccs_audit_env_log(r, env, !error);
		if (!error)
			break;
		error = ccs_supervisor(r, CCS_KEYWORD_ALLOW_ENV "%s\n", env);
	} while (error == CCS_RETRY_REQUEST);
	return error;
}

/**
 * ccs_write_env_policy - Write "struct ccs_env_acl" list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_env_policy(char *data, struct ccs_domain_info *domain,
			 struct ccs_condition *condition,
			 const bool is_delete)
{
	struct ccs_acl_info *ptr;
	struct ccs_env_acl e = {
		.head.type = CCS_TYPE_ENV_ACL,
		.head.cond = condition
	};
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!ccs_is_correct_path(data, 0, 0, 0) || strchr(data, '='))
		return -EINVAL;
	e.env = ccs_get_name(data);
	if (!e.env)
		return error;
	if (mutex_lock_interruptible(&ccs_policy_lock))
		goto out;
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_env_acl *acl =
			container_of(ptr, struct ccs_env_acl, head);
		if (ptr->type != CCS_TYPE_ENV_ACL || ptr->cond != condition ||
		    acl->env != e.env)
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error) {
		struct ccs_env_acl *entry = ccs_commit_ok(&e, sizeof(e));
		if (entry) {
			ccs_add_domain_acl(domain, &entry->head);
			error = 0;
		}
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name(e.env);
	return error;
}
