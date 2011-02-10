/*
 * security/ccsecurity/path_group.c
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.7.2   2010/04/01
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include "internal.h"
/* The list for "struct ccs_path_group". */
LIST_HEAD(ccs_path_group_list);

/**
 * ccs_get_path_group - Allocate memory for "struct ccs_path_group".
 *
 * @group_name: The name of pathname group.
 *
 * Returns pointer to "struct ccs_path_group" on success, NULL otherwise.
 */
struct ccs_path_group *ccs_get_path_group(const char *group_name)
{
	struct ccs_path_group *entry = NULL;
	struct ccs_path_group *group = NULL;
	const struct ccs_path_info *saved_group_name;
	int error = -ENOMEM;
	if (!ccs_is_correct_path(group_name, 0, 0, 0) ||
	    !group_name[0])
		return NULL;
	saved_group_name = ccs_get_name(group_name);
	if (!saved_group_name)
		return NULL;
	entry = kzalloc(sizeof(*entry), CCS_GFP_FLAGS);
	if (mutex_lock_interruptible(&ccs_policy_lock))
		goto out;
	list_for_each_entry_rcu(group, &ccs_path_group_list, list) {
		if (saved_group_name != group->group_name)
			continue;
		atomic_inc(&group->users);
		error = 0;
		break;
	}
	if (error && ccs_memory_ok(entry, sizeof(*entry))) {
		INIT_LIST_HEAD(&entry->member_list);
		entry->group_name = saved_group_name;
		saved_group_name = NULL;
		atomic_set(&entry->users, 1);
		list_add_tail_rcu(&entry->list, &ccs_path_group_list);
		group = entry;
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name(saved_group_name);
	kfree(entry);
	return !error ? group : NULL;
}

/**
 * ccs_write_path_group_policy - Write "struct ccs_path_group" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, nagative value otherwise.
 */
int ccs_write_path_group_policy(char *data, const bool is_delete)
{
	struct ccs_path_group *group;
	struct ccs_path_group_member *member;
	struct ccs_path_group_member e = { };
	int error = is_delete ? -ENOENT : -ENOMEM;
	char *w[2];
	if (!ccs_tokenize(data, w, sizeof(w)) || !w[1][0])
		return -EINVAL;
	group = ccs_get_path_group(w[0]);
	if (!group)
		return -ENOMEM;
	e.member_name = ccs_get_name(w[1]);
	if (!e.member_name)
		goto out;
	if (mutex_lock_interruptible(&ccs_policy_lock))
		goto out;
	list_for_each_entry_rcu(member, &group->member_list, list) {
		if (member->member_name != e.member_name)
			continue;
		member->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error) {
		struct ccs_path_group_member *entry =
			ccs_commit_ok(&e, sizeof(e));
		if (entry) {
			list_add_tail_rcu(&entry->list, &group->member_list);
			error = 0;
		}
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name(e.member_name);
	ccs_put_path_group(group);
	return error;
}

/**
 * ccs_read_path_group_policy - Read "struct ccs_path_group" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_read_path_group_policy(struct ccs_io_buffer *head)
{
	struct list_head *gpos;
	struct list_head *mpos;
	list_for_each_cookie(gpos, head->read_var1, &ccs_path_group_list) {
		struct ccs_path_group *group;
		group = list_entry(gpos, struct ccs_path_group, list);
		list_for_each_cookie(mpos, head->read_var2,
				     &group->member_list) {
			struct ccs_path_group_member *member;
			member = list_entry(mpos, struct ccs_path_group_member,
					    list);
			if (member->is_deleted)
				continue;
			if (!ccs_io_printf(head, CCS_KEYWORD_PATH_GROUP
					   "%s %s\n",
					   group->group_name->name,
					   member->member_name->name))
				return false;
		}
	}
	return true;
}

/**
 * ccs_path_matches_group - Check whether the given pathname matches members of the given pathname group.
 *
 * @pathname:        The name of pathname.
 * @group:           Pointer to "struct ccs_path_group".
 * @may_use_pattern: True if wild card is permitted.
 *
 * Returns true if @pathname matches pathnames in @group, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_path_matches_group(const struct ccs_path_info *pathname,
			    const struct ccs_path_group *group,
			    const bool may_use_pattern)
{
	struct ccs_path_group_member *member;
	bool matched = false;
	list_for_each_entry_rcu(member, &group->member_list, list) {
		if (member->is_deleted)
			continue;
		if (!member->member_name->is_patterned) {
			if (ccs_pathcmp(pathname, member->member_name))
				continue;
		} else if (may_use_pattern) {
			if (!ccs_path_matches_pattern(pathname,
						      member->member_name))
				continue;
		} else
			continue;
		matched = true;
		break;
	}
	return matched;
}
