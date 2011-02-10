/*
 * security/ccsecurity/autobind.c
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

/* The list for "struct ccs_reserved_entry". */
LIST_HEAD(ccs_reservedport_list);

static u8 ccs_reserved_port_map[8192];

/**
 * ccs_lport_reserved - Check permission for bind()'s automatic port number selection.
 *
 * @port: Port number.
 *
 * Returns true on success, false otherwise.
 */
static bool __ccs_lport_reserved(const u16 port)
{
	return ccs_reserved_port_map[port >> 3] & (1 << (port & 7))
		? true : false;
}

/**
 * ccs_update_reserved_entry - Update "struct ccs_reserved_entry" list.
 *
 * @min_port: Start of port number range.
 * @max_port: End of port number range.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_reserved_entry(const u16 min_port, const u16 max_port,
				     const bool is_delete)
{
	struct ccs_reserved_entry *ptr;
	struct ccs_reserved_entry e = {
		.min_port = min_port,
		.max_port = max_port
	};
	int error = is_delete ? -ENOENT : -ENOMEM;
	u8 *ccs_tmp_map = kzalloc(8192, CCS_GFP_FLAGS);
	if (!ccs_tmp_map)
		return -ENOMEM;
	if (mutex_lock_interruptible(&ccs_policy_lock))
		goto out;
	list_for_each_entry_rcu(ptr, &ccs_reservedport_list, list) {
		if (ptr->min_port != min_port || ptr->max_port != max_port)
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error) {
		struct ccs_reserved_entry *entry =
			ccs_commit_ok(&e, sizeof(e));
		if (entry) {
			list_add_tail_rcu(&entry->list,
					  &ccs_reservedport_list);
			error = 0;
		}
	}
	list_for_each_entry_rcu(ptr, &ccs_reservedport_list, list) {
		unsigned int port;
		if (ptr->is_deleted)
			continue;
		for (port = ptr->min_port; port <= ptr->max_port; port++)
			ccs_tmp_map[port >> 3] |= 1 << (port & 7);
	}
	memmove(ccs_reserved_port_map, ccs_tmp_map,
		sizeof(ccs_reserved_port_map));
	/*
	 * Since this feature is no-op by default, we don't need to register
	 * this callback hook unless the first entry is added.
	 */
	ccsecurity_ops.lport_reserved = __ccs_lport_reserved;
	mutex_unlock(&ccs_policy_lock);
 out:
	kfree(ccs_tmp_map);
	return error;
}

/**
 * ccs_write_reserved_port_policy - Write "struct ccs_reserved_entry" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_reserved_port_policy(char *data, const bool is_delete)
{
	unsigned int from;
	unsigned int to;
	if (strchr(data, ' '))
		goto out;
	if (sscanf(data, "%u-%u", &from, &to) == 2) {
		if (from <= to && to < 65536)
			return ccs_update_reserved_entry(from, to, is_delete);
	} else if (sscanf(data, "%u", &from) == 1) {
		if (from < 65536)
			return ccs_update_reserved_entry(from, from,
							 is_delete);
	}
 out:
	return -EINVAL;
}

/**
 * ccs_read_reserved_port_policy - Read "struct ccs_reserved_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_read_reserved_port_policy(struct ccs_io_buffer *head)
{
	struct list_head *pos;
	char buffer[16];
	memset(buffer, 0, sizeof(buffer));
	list_for_each_cookie(pos, head->read_var2, &ccs_reservedport_list) {
		u16 min_port;
		u16 max_port;
		struct ccs_reserved_entry *ptr;
		ptr = list_entry(pos, struct ccs_reserved_entry, list);
		if (ptr->is_deleted)
			continue;
		min_port = ptr->min_port;
		max_port = ptr->max_port;
		snprintf(buffer, sizeof(buffer) - 1, "%u%c%u", min_port,
			 min_port != max_port ? '-' : '\0', max_port);
		if (!ccs_io_printf(head, CCS_KEYWORD_DENY_AUTOBIND "%s\n",
				   buffer))
			return false;
	}
	return true;
}
