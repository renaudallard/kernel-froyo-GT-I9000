/*
 * security/ccsecurity/address_group.c
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

/* The list for "struct ccs_address_group". */
LIST_HEAD(ccs_address_group_list);

/**
 * ccs_get_address_group - Allocate memory for "struct ccs_address_group".
 *
 * @group_name: The name of address group.
 *
 * Returns pointer to "struct ccs_address_group" on success,
 * NULL otherwise.
 */
struct ccs_address_group *ccs_get_address_group(const char *group_name)
{
	struct ccs_address_group *entry = NULL;
	struct ccs_address_group *group = NULL;
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
	list_for_each_entry_rcu(group, &ccs_address_group_list, list) {
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
		list_add_tail_rcu(&entry->list, &ccs_address_group_list);
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
 * ccs_write_address_group_policy - Write "struct ccs_address_group" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_address_group_policy(char *data, const bool is_delete)
{
	struct ccs_address_group *group;
	struct ccs_address_group_member *member;
	struct ccs_address_group_member e = { };
	int error = is_delete ? -ENOENT : -ENOMEM;
	u16 min_address[8];
	u16 max_address[8];
	char *w[2];
	if (!ccs_tokenize(data, w, sizeof(w)) || !w[1][0])
		return -EINVAL;
	group = ccs_get_address_group(w[0]);
	if (!group)
		return -ENOMEM;
	switch (ccs_parse_ip_address(w[1], min_address, max_address)) {
	case 2:
		e.is_ipv6 = true;
		e.min.ipv6 = ccs_get_ipv6_address((struct in6_addr *)
						  min_address);
		e.max.ipv6 = ccs_get_ipv6_address((struct in6_addr *)
						  max_address);
		if (!e.min.ipv6 || !e.max.ipv6)
			goto out;
		break;
	case 1:
		e.min.ipv4 = ntohl(*(u32 *) min_address);
		e.max.ipv4 = ntohl(*(u32 *) max_address);
		break;
	default:
		goto out;
	}
	if (mutex_lock_interruptible(&ccs_policy_lock))
		goto out;
	list_for_each_entry_rcu(member, &group->member_list, list) {
		if (!ccs_is_same_address_group_member(member, &e))
			continue;
		member->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error) {
		struct ccs_address_group_member *entry =
			ccs_commit_ok(&e, sizeof(e));
		if (entry) {
			list_add_tail_rcu(&entry->list, &group->member_list);
			error = 0;
		}
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	if (e.is_ipv6) {
		ccs_put_ipv6_address(e.min.ipv6);
		ccs_put_ipv6_address(e.max.ipv6);
	}
	ccs_put_address_group(group);
	return error;
}

/**
 * ccs_read_address_group_policy - Read "struct ccs_address_group" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_read_address_group_policy(struct ccs_io_buffer *head)
{
	struct list_head *gpos;
	struct list_head *mpos;
	list_for_each_cookie(gpos, head->read_var1, &ccs_address_group_list) {
		struct ccs_address_group *group;
		group = list_entry(gpos, struct ccs_address_group, list);
		list_for_each_cookie(mpos, head->read_var2,
				     &group->member_list) {
			char buf[128];
			struct ccs_address_group_member *member;
			member = list_entry(mpos,
					    struct ccs_address_group_member,
					    list);
			if (member->is_deleted)
				continue;
			if (member->is_ipv6) {
				const struct in6_addr *min_address
					= member->min.ipv6;
				const struct in6_addr *max_address
					= member->max.ipv6;
				ccs_print_ipv6(buf, sizeof(buf), min_address);
				if (min_address != max_address) {
					int len;
					char *cp = buf + strlen(buf);
					*cp++ = '-';
					len = strlen(buf);
					ccs_print_ipv6(cp, sizeof(buf) - len,
						       max_address);
				}
			} else {
				const u32 min_address = member->min.ipv4;
				const u32 max_address = member->max.ipv4;
				memset(buf, 0, sizeof(buf));
				snprintf(buf, sizeof(buf) - 1, "%u.%u.%u.%u",
					 HIPQUAD(min_address));
				if (min_address != max_address) {
					const int len = strlen(buf);
					snprintf(buf + len,
						 sizeof(buf) - 1 - len,
						 "-%u.%u.%u.%u",
						 HIPQUAD(max_address));
				}
			}
			if (!ccs_io_printf(head, CCS_KEYWORD_ADDRESS_GROUP
					   "%s %s\n", group->group_name->name,
					   buf))
				return false;
		}
	}
	return true;
}

/**
 * ccs_address_matches_group - Check whether the given address matches members of the given address group.
 *
 * @is_ipv6: True if @address is an IPv6 address.
 * @address: An IPv4 or IPv6 address.
 * @group:   Pointer to "struct ccs_address_group".
 *
 * Returns true if @address matches addresses in @group group, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_address_matches_group(const bool is_ipv6, const u32 *address,
			       const struct ccs_address_group *group)
{
	struct ccs_address_group_member *member;
	const u32 ip = ntohl(*address);
	bool matched = false;
	list_for_each_entry_rcu(member, &group->member_list, list) {
		if (member->is_deleted)
			continue;
		if (member->is_ipv6) {
			if (is_ipv6 &&
			    memcmp(member->min.ipv6, address, 16) <= 0 &&
			    memcmp(address, member->max.ipv6, 16) <= 0) {
				matched = true;
				break;
			}
		} else {
			if (!is_ipv6 &&
			    member->min.ipv4 <= ip && ip <= member->max.ipv4) {
				matched = true;
				break;
			}
		}
	}
	return matched;
}
