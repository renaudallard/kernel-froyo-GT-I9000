/*
 * security/ccsecurity/number_group.c
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.7.2   2010/04/01
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/slab.h>
#include "internal.h"

/* The list for "struct ccs_number_group". */
LIST_HEAD(ccs_number_group_list);

/**
 * ccs_get_number_group - Allocate memory for "struct ccs_number_group".
 *
 * @group_name: The name of number group.
 *
 * Returns pointer to "struct ccs_number_group" on success,
 * NULL otherwise.
 */
struct ccs_number_group *ccs_get_number_group(const char *group_name)
{
	struct ccs_number_group *entry = NULL;
	struct ccs_number_group *group = NULL;
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
	list_for_each_entry_rcu(group, &ccs_number_group_list, list) {
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
		list_add_tail_rcu(&entry->list, &ccs_number_group_list);
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
 * ccs_write_number_group_policy - Write "struct ccs_number_group" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, nagative value otherwise.
 */
int ccs_write_number_group_policy(char *data, const bool is_delete)
{
	struct ccs_number_group *group;
	struct ccs_number_group_member e = { };
	struct ccs_number_group_member *member;
	int error = is_delete ? -ENOENT : -ENOMEM;
	char *w[2];
	if (!ccs_tokenize(data, w, sizeof(w)))
		return -EINVAL;
	if (!ccs_parse_number_union(w[1], &e.number))
		return -EINVAL;
	if (e.number.is_group || e.number.values[0] > e.number.values[1]) {
		ccs_put_number_union(&e.number);
		return -EINVAL;
	}
	group = ccs_get_number_group(w[0]);
	if (!group)
		return -ENOMEM;
	if (mutex_lock_interruptible(&ccs_policy_lock))
		goto out;
	list_for_each_entry_rcu(member, &group->member_list, list) {
		if (memcmp(&member->number, &e.number, sizeof(e.number)))
			continue;
		member->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error) {
		struct ccs_number_group_member *entry =
			ccs_commit_ok(&e, sizeof(e));
		if (entry) {
			list_add_tail_rcu(&entry->list, &group->member_list);
			error = 0;
		}
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_number_group(group);
	return error;
}

/**
 * ccs_read_number_group_policy - Read "struct ccs_number_group" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_read_number_group_policy(struct ccs_io_buffer *head)
{
	struct list_head *gpos;
	struct list_head *mpos;
	list_for_each_cookie(gpos, head->read_var1, &ccs_number_group_list) {
		struct ccs_number_group *group;
		const char *name;
		group = list_entry(gpos, struct ccs_number_group, list);
		name = group->group_name->name;
		list_for_each_cookie(mpos, head->read_var2,
				     &group->member_list) {
			int pos;
			const struct ccs_number_group_member *member
				= list_entry(mpos,
					     struct ccs_number_group_member,
					     list);
			if (member->is_deleted)
				continue;
			pos = head->read_avail;
			if (!ccs_io_printf(head, CCS_KEYWORD_NUMBER_GROUP "%s",
					   name) ||
			    !ccs_print_number_union(head, &member->number) ||
			    !ccs_io_printf(head, "\n")) {
				head->read_avail = pos;
				return false;
			}
		}
	}
	return true;
}

/**
 * ccs_number_matches_group - Check whether the given number matches members of the given number group.
 *
 * @min:   Min number.
 * @max:   Max number.
 * @group: Pointer to "struct ccs_number_group".
 *
 * Returns true if @min and @max partially overlaps @group, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_number_matches_group(const unsigned long min, const unsigned long max,
			      const struct ccs_number_group *group)
{
	struct ccs_number_group_member *member;
	bool matched = false;
	list_for_each_entry_rcu(member, &group->member_list, list) {
		if (member->is_deleted)
			continue;
		if (min > member->number.values[1] ||
		    max < member->number.values[0])
			continue;
		matched = true;
		break;
	}
	return matched;
}
