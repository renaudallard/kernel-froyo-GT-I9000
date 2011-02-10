/*
 * security/ccsecurity/memory.c
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0) || defined(RHEL_MAJOR)
#include <linux/hash.h>
#endif

/**
 * ccs_warn_oom - Print out of memory warning message.
 *
 * @function: Function's name.
 */
void ccs_warn_oom(const char *function)
{
	/* Reduce error messages. */
	static pid_t ccs_last_pid;
	const pid_t pid = current->pid;
	if (ccs_last_pid != pid) {
		printk(KERN_WARNING "ERROR: Out of memory at %s.\n",
		       function);
		ccs_last_pid = pid;
	}
	if (!ccs_policy_loaded)
		panic("MAC Initialization failed.\n");
}

/* Memory allocated for policy. */
static atomic_t ccs_policy_memory_size;
/* Quota for holding policy. */
static unsigned int ccs_quota_for_policy;

/**
 * ccs_memory_ok - Check memory quota.
 *
 * @ptr:  Pointer to allocated memory.
 * @size: Size in byte.
 *
 * Returns true if @ptr is not NULL and quota not exceeded, false otherwise.
 */
bool ccs_memory_ok(const void *ptr, const unsigned int size)
{
	size_t s = ccs_round2(size);
	atomic_add(s, &ccs_policy_memory_size);
	if (ptr && (!ccs_quota_for_policy ||
		    atomic_read(&ccs_policy_memory_size)
		    <= ccs_quota_for_policy))
		return true;
	atomic_sub(s, &ccs_policy_memory_size);
	ccs_warn_oom(__func__);
	return false;
}

/**
 * ccs_commit_ok - Allocate memory and check memory quota.
 *
 * @data:   Data to copy from.
 * @size:   Size in byte.
 *
 * Returns pointer to allocated memory on success, NULL otherwise.
 * @data is zero-cleared on success.
 */
void *ccs_commit_ok(void *data, const unsigned int size)
{
	void *ptr = kmalloc(size, CCS_GFP_FLAGS);
	if (ccs_memory_ok(ptr, size)) {
		memmove(ptr, data, size);
		memset(data, 0, size);
		return ptr;
	}
	kfree(ptr);
	return NULL;
}

/**
 * ccs_memory_free - Free memory for elements.
 *
 * @ptr:  Pointer to allocated memory.
 * @size: Size in byte.
 */
void ccs_memory_free(const void *ptr, size_t size)
{
	atomic_sub(ccs_round2(size), &ccs_policy_memory_size);
	kfree(ptr);
}

/* List of IPv6 address. */
LIST_HEAD(ccs_address_list);

/**
 * ccs_get_ipv6_address - Keep the given IPv6 address on the RAM.
 *
 * @addr: Pointer to "struct in6_addr".
 *
 * Returns pointer to "struct in6_addr" on success, NULL otherwise.
 *
 * The RAM is shared, so NEVER try to modify or kfree() the returned address.
 */
const struct in6_addr *ccs_get_ipv6_address(const struct in6_addr *addr)
{
	struct ccs_ipv6addr_entry *entry;
	struct ccs_ipv6addr_entry *ptr = NULL;
	int error = -ENOMEM;
	if (!addr)
		return NULL;
	entry = kzalloc(sizeof(*entry), CCS_GFP_FLAGS);
	if (mutex_lock_interruptible(&ccs_policy_lock))
		goto out;
	list_for_each_entry(ptr, &ccs_address_list, list) {
		if (memcmp(&ptr->addr, addr, sizeof(*addr)))
			continue;
		atomic_inc(&ptr->users);
		error = 0;
		break;
	}
	if (error && ccs_memory_ok(entry, sizeof(*entry))) {
		ptr = entry;
		ptr->addr = *addr;
		atomic_set(&ptr->users, 1);
		list_add_tail(&ptr->list, &ccs_address_list);
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	kfree(entry);
	return !error ? &ptr->addr : NULL;
}

/* The list for "struct ccs_name_entry". */
struct list_head ccs_name_list[CCS_MAX_HASH];

/**
 * ccs_get_name - Allocate memory for string data.
 *
 * @name: The string to store into the permernent memory.
 *
 * Returns pointer to "struct ccs_path_info" on success, NULL otherwise.
 */
const struct ccs_path_info *ccs_get_name(const char *name)
{
	struct ccs_name_entry *ptr;
	unsigned int hash;
	int len;
	int allocated_len;
	struct list_head *head;

	if (!name)
		return NULL;
	len = strlen(name) + 1;
	hash = full_name_hash((const unsigned char *) name, len - 1);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0) || defined(RHEL_MAJOR)
	head = &ccs_name_list[hash_long(hash, CCS_HASH_BITS)];
#else
	head = &ccs_name_list[hash % CCS_MAX_HASH];
#endif
	if (mutex_lock_interruptible(&ccs_policy_lock))
		return NULL;
	list_for_each_entry(ptr, head, list) {
		if (hash != ptr->entry.hash || strcmp(name, ptr->entry.name))
			continue;
		atomic_inc(&ptr->users);
		goto out;
	}
	allocated_len = ccs_round2(sizeof(*ptr) + len);
	ptr = kzalloc(allocated_len, CCS_GFP_FLAGS);
	if (!ptr || (ccs_quota_for_policy &&
		     atomic_read(&ccs_policy_memory_size) + allocated_len
		     > ccs_quota_for_policy)) {
		kfree(ptr);
		ptr = NULL;
		ccs_warn_oom(__func__);
		goto out;
	}
	atomic_add(allocated_len, &ccs_policy_memory_size);
	ptr->entry.name = ((char *) ptr) + sizeof(*ptr);
	memmove((char *) ptr->entry.name, name, len);
	atomic_set(&ptr->users, 1);
	ccs_fill_path_info(&ptr->entry);
	ptr->size = allocated_len;
	list_add_tail(&ptr->list, head);
 out:
	mutex_unlock(&ccs_policy_lock);
	return ptr ? &ptr->entry : NULL;
}

/**
 * ccs_mm_init - Initialize mm related code.
 */
void __init ccs_mm_init(void)
{
	int idx;
	for (idx = 0; idx < CCS_MAX_HASH; idx++)
		INIT_LIST_HEAD(&ccs_name_list[idx]);
	INIT_LIST_HEAD(&ccs_kernel_domain.acl_info_list);
	ccs_kernel_domain.domainname = ccs_get_name(ROOT_NAME);
	list_add_tail_rcu(&ccs_kernel_domain.list, &ccs_domain_list);
	idx = ccs_read_lock();
	if (ccs_find_domain(ROOT_NAME) != &ccs_kernel_domain)
		panic("Can't register ccs_kernel_domain");
	{
		/* Load built-in policy. */
		static char ccs_builtin_initializers[] __initdata
			= CONFIG_CCSECURITY_BUILTIN_INITIALIZERS;
		char *cp = ccs_builtin_initializers;
		ccs_normalize_line(cp);
		while (cp && *cp) {
			char *cp2 = strchr(cp, ' ');
			if (cp2)
				*cp2++ = '\0';
			ccs_write_domain_initializer_policy(cp, false, false);
			cp = cp2;
		}
	}
	ccs_read_unlock(idx);
}

/* Memory allocated for audit logs. */
unsigned int ccs_audit_log_memory_size;
/* Quota for holding audit logs. */
unsigned int ccs_quota_for_audit_log;

/* Memory allocated for query lists. */
unsigned int ccs_query_memory_size;
/* Quota for holding query lists. */
unsigned int ccs_quota_for_query;

/**
 * ccs_read_memory_counter - Check for memory usage.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 */
void ccs_read_memory_counter(struct ccs_io_buffer *head)
{
	const unsigned int usage[3] = {
		atomic_read(&ccs_policy_memory_size),
		ccs_audit_log_memory_size,
		ccs_query_memory_size
	};
	const unsigned int quota[3] = {
		ccs_quota_for_policy,
		ccs_quota_for_audit_log,
		ccs_quota_for_query
	};
	static const char *header[4] = {
		"Policy:     ",
		"Audit logs: ",
		"Query lists:",
		"Total:      "
	};
	unsigned int total = 0;
	int i;
	if (head->read_eof)
		return;
	for (i = 0; i < 3; i++) {
		total += usage[i];
		ccs_io_printf(head, "%s %10u", header[i], usage[i]);
		if (quota[i])
			ccs_io_printf(head, "   (Quota: %10u)", quota[i]);
		ccs_io_printf(head, "\n");
	}
	ccs_io_printf(head, "%s %10u\n", header[3], total);
	head->read_eof = true;
}

/**
 * ccs_write_memory_quota - Set memory quota.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0.
 */
int ccs_write_memory_quota(struct ccs_io_buffer *head)
{
	char *data = head->write_buf;
	unsigned int size;
	if (sscanf(data, "Policy: %u", &size) == 1)
		ccs_quota_for_policy = size;
	else if (sscanf(data, "Audit logs: %u", &size) == 1)
		ccs_quota_for_audit_log = size;
	else if (sscanf(data, "Query lists: %u", &size) == 1)
		ccs_quota_for_query = size;
	return 0;
}
