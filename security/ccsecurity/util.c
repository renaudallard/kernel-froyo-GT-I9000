/*
 * security/ccsecurity/util.c
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

/* Lock for protecting policy. */
DEFINE_MUTEX(ccs_policy_lock);

/* Has /sbin/init started? */
bool ccs_policy_loaded;

/* Index table for searching parent category. */
static const u8 ccs_index2category[CCS_MAX_MAC_INDEX +
				   CCS_MAX_CAPABILITY_INDEX] = {
	[CCS_MAC_FILE_EXECUTE]    = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_OPEN]       = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_CREATE]     = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_UNLINK]     = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_MKDIR]      = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_RMDIR]      = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_MKFIFO]     = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_MKSOCK]     = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_TRUNCATE]   = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_SYMLINK]    = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_REWRITE]    = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_MKBLOCK]    = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_MKCHAR]     = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_LINK]       = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_RENAME]     = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_CHMOD]      = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_CHOWN]      = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_CHGRP]      = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_IOCTL]      = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_CHROOT]     = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_MOUNT]      = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_UMOUNT]     = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_PIVOT_ROOT] = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_ENVIRON]         = CCS_MAC_CATEGORY_MISC,
	[CCS_MAC_NETWORK_UDP_BIND]    = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UDP_CONNECT] = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_TCP_BIND]    = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_TCP_LISTEN]  = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_TCP_CONNECT] = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_TCP_ACCEPT]  = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_RAW_BIND]    = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_RAW_CONNECT] = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_SIGNAL]          = CCS_MAC_CATEGORY_IPC,
	[CCS_MAX_MAC_INDEX + CCS_INET_STREAM_SOCKET_CREATE]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_INET_STREAM_SOCKET_LISTEN]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_INET_STREAM_SOCKET_CONNECT]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_USE_INET_DGRAM_SOCKET]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_USE_INET_RAW_SOCKET]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_USE_ROUTE_SOCKET]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_USE_PACKET_SOCKET]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_SYS_MOUNT]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_SYS_UMOUNT]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_SYS_REBOOT]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_SYS_CHROOT]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_SYS_KILL]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_SYS_VHANGUP]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_SYS_SETTIME]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_SYS_NICE]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_SYS_SETHOSTNAME]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_USE_KERNEL_MODULE]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_CREATE_FIFO]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_CREATE_BLOCK_DEV]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_CREATE_CHAR_DEV]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_CREATE_UNIX_SOCKET]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_SYS_LINK]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_SYS_SYMLINK]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_SYS_RENAME]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_SYS_UNLINK]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_SYS_CHMOD]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_SYS_CHOWN]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_SYS_IOCTL]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_SYS_KEXEC_LOAD]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_SYS_PIVOT_ROOT]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_SYS_PTRACE]
	= CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAX_MAC_INDEX + CCS_CONCEAL_MOUNT]
	= CCS_MAC_CATEGORY_CAPABILITY,
};

/* Utility functions. */

/**
 * ccs_parse_ulong - Parse an "unsigned long" value.
 *
 * @result: Pointer to "unsigned long".
 * @str:    Pointer to string to parse.
 *
 * Returns value type on success, 0 otherwise.
 *
 * The @src is updated to point the first character after the value
 * on success.
 */
u8 ccs_parse_ulong(unsigned long *result, char **str)
{
	const char *cp = *str;
	char *ep;
	int base = 10;
	if (*cp == '0') {
		char c = *(cp + 1);
		if (c == 'x' || c == 'X') {
			base = 16;
			cp += 2;
		} else if (c >= '0' && c <= '7') {
			base = 8;
			cp++;
		}
	}
	*result = simple_strtoul(cp, &ep, base);
	if (cp == ep)
		return 0;
	*str = ep;
	switch (base) {
	case 16:
		return CCS_VALUE_TYPE_HEXADECIMAL;
	case 8:
		return CCS_VALUE_TYPE_OCTAL;
	default:
		return CCS_VALUE_TYPE_DECIMAL;
	}
}

/**
 * ccs_print_ulong - Print an "unsigned long" value.
 *
 * @buffer:     Pointer to buffer.
 * @buffer_len: Size of @buffer.
 * @value:      An "unsigned long" value.
 * @type:       Type of @value.
 *
 * Returns nothing.
 */
void ccs_print_ulong(char *buffer, const int buffer_len,
		     const unsigned long value, const u8 type)
{
	if (type == CCS_VALUE_TYPE_DECIMAL)
		snprintf(buffer, buffer_len, "%lu", value);
	else if (type == CCS_VALUE_TYPE_OCTAL)
		snprintf(buffer, buffer_len, "0%lo", value);
	else if (type == CCS_VALUE_TYPE_HEXADECIMAL)
		snprintf(buffer, buffer_len, "0x%lX", value);
	else
		snprintf(buffer, buffer_len, "type(%u)", type);
}

/**
 * ccs_parse_name_union - Parse a ccs_name_union.
 *
 * @filename: Name or name group.
 * @ptr:      Pointer to "struct ccs_name_union".
 *
 * Returns true on success, false otherwise.
 */
bool ccs_parse_name_union(const char *filename, struct ccs_name_union *ptr)
{
	if (!ccs_is_correct_path(filename, 0, 0, 0))
		return false;
	if (filename[0] == '@') {
		ptr->group = ccs_get_path_group(filename + 1);
		ptr->is_group = true;
		return ptr->group != NULL;
	}
	ptr->filename = ccs_get_name(filename);
	ptr->is_group = false;
	return ptr->filename != NULL;
}

/**
 * ccs_parse_number_union - Parse a ccs_number_union.
 *
 * @data: Number or number range or number group.
 * @ptr:  Pointer to "struct ccs_number_union".
 *
 * Returns true on success, false otherwise.
 */
bool ccs_parse_number_union(char *data, struct ccs_number_union *num)
{
	u8 type;
	unsigned long v;
	memset(num, 0, sizeof(*num));
	if (data[0] == '@') {
		if (!ccs_is_correct_path(data, 0, 0, 0))
			return false;
		num->group = ccs_get_number_group(data + 1);
		num->is_group = true;
		return num->group != NULL;
	}
	type = ccs_parse_ulong(&v, &data);
	if (!type)
		return false;
	num->values[0] = v;
	num->min_type = type;
	if (!*data) {
		num->values[1] = v;
		num->max_type = type;
		return true;
	}
	if (*data++ != '-')
		return false;
	type = ccs_parse_ulong(&v, &data);
	if (!type || *data)
		return false;
	num->values[1] = v;
	num->max_type = type;
	return true;
}

/**
 * ccs_is_byte_range - Check whether the string is a \ooo style octal value.
 *
 * @str: Pointer to the string.
 *
 * Returns true if @str is a \ooo style octal value, false otherwise.
 */
static inline bool ccs_is_byte_range(const char *str)
{
	return *str >= '0' && *str++ <= '3' &&
		*str >= '0' && *str++ <= '7' &&
		*str >= '0' && *str <= '7';
}

/**
 * ccs_is_decimal - Check whether the character is a decimal character.
 *
 * @c: The character to check.
 *
 * Returns true if @c is a decimal character, false otherwise.
 */
static inline bool ccs_is_decimal(const char c)
{
	return c >= '0' && c <= '9';
}

/**
 * ccs_is_hexadecimal - Check whether the character is a hexadecimal character.
 *
 * @c: The character to check.
 *
 * Returns true if @c is a hexadecimal character, false otherwise.
 */
static inline bool ccs_is_hexadecimal(const char c)
{
	return (c >= '0' && c <= '9') ||
		(c >= 'A' && c <= 'F') ||
		(c >= 'a' && c <= 'f');
}

/**
 * ccs_is_alphabet_char - Check whether the character is an alphabet.
 *
 * @c: The character to check.
 *
 * Returns true if @c is an alphabet character, false otherwise.
 */
static inline bool ccs_is_alphabet_char(const char c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

/**
 * ccs_make_byte - Make byte value from three octal characters.
 *
 * @c1: The first character.
 * @c2: The second character.
 * @c3: The third character.
 *
 * Returns byte value.
 */
static inline u8 ccs_make_byte(const u8 c1, const u8 c2, const u8 c3)
{
	return ((c1 - '0') << 6) + ((c2 - '0') << 3) + (c3 - '0');
}

/**
 * ccs_str_starts - Check whether the given string starts with the given keyword.
 *
 * @src:  Pointer to pointer to the string.
 * @find: Pointer to the keyword.
 *
 * Returns true if @src starts with @find, false otherwise.
 *
 * The @src is updated to point the first character after the @find
 * if @src starts with @find.
 */
bool ccs_str_starts(char **src, const char *find)
{
	const int len = strlen(find);
	char *tmp = *src;
	if (strncmp(tmp, find, len))
		return false;
	tmp += len;
	*src = tmp;
	return true;
}

/**
 * ccs_normalize_line - Format string.
 *
 * @buffer: The line to normalize.
 *
 * Leading and trailing whitespaces are removed.
 * Multiple whitespaces are packed into single space.
 *
 * Returns nothing.
 */
void ccs_normalize_line(unsigned char *buffer)
{
	unsigned char *sp = buffer;
	unsigned char *dp = buffer;
	bool first = true;
	while (*sp && (*sp <= ' ' || *sp >= 127))
		sp++;
	while (*sp) {
		if (!first)
			*dp++ = ' ';
		first = false;
		while (*sp > ' ' && *sp < 127)
			*dp++ = *sp++;
		while (*sp && (*sp <= ' ' || *sp >= 127))
			sp++;
	}
	*dp = '\0';
}

/**
 * ccs_tokenize - Tokenize string.
 *
 * @buffer: The line to tokenize.
 * @w:      Pointer to "char *".
 * @size:   Sizeof @w .
 *
 * Returns true on success, false otherwise.
 */
bool ccs_tokenize(char *buffer, char *w[], size_t size)
{
	int count = size / sizeof(char *);
	int i;
	for (i = 0; i < count; i++)
		w[i] = "";
	for (i = 0; i < count; i++) {
		char *cp = strchr(buffer, ' ');
		if (cp)
			*cp = '\0';
		w[i] = buffer;
		if (!cp)
			break;
		buffer = cp + 1;
	}
	return i < count || !*buffer;
}

/**
 * ccs_is_correct_path - Validate a pathname.
 *
 * @filename:     The pathname to check.
 * @start_type:   Should the pathname start with '/'?
 *                1 = must / -1 = must not / 0 = don't care
 * @pattern_type: Can the pathname contain a wildcard?
 *                1 = must / -1 = must not / 0 = don't care
 * @end_type:     Should the pathname end with '/'?
 *                1 = must / -1 = must not / 0 = don't care
 *
 * Check whether the given filename follows the naming rules.
 * Returns true if @filename follows the naming rules, false otherwise.
 */
bool ccs_is_correct_path(const char *filename, const s8 start_type,
			 const s8 pattern_type, const s8 end_type)
{
	const char *const start = filename;
	bool in_repetition = false;
	bool contains_pattern = false;
	unsigned char c;
	unsigned char d;
	unsigned char e;
	if (!filename)
		goto out;
	c = *filename;
	if (start_type == 1) { /* Must start with '/' */
		if (c != '/')
			goto out;
	} else if (start_type == -1) { /* Must not start with '/' */
		if (c == '/')
			goto out;
	}
	if (c)
		c = *(filename + strlen(filename) - 1);
	if (end_type == 1) { /* Must end with '/' */
		if (c != '/')
			goto out;
	} else if (end_type == -1) { /* Must not end with '/' */
		if (c == '/')
			goto out;
	}
	while (1) {
		c = *filename++;
		if (!c)
			break;
		if (c == '\\') {
			c = *filename++;
			switch (c) {
			case '\\':  /* "\\" */
				continue;
			case '$':   /* "\$" */
			case '+':   /* "\+" */
			case '?':   /* "\?" */
			case '*':   /* "\*" */
			case '@':   /* "\@" */
			case 'x':   /* "\x" */
			case 'X':   /* "\X" */
			case 'a':   /* "\a" */
			case 'A':   /* "\A" */
			case '-':   /* "\-" */
				if (pattern_type == -1)
					break; /* Must not contain pattern */
				contains_pattern = true;
				continue;
			case '{':   /* "/\{" */
				if (filename - 3 < start ||
				    *(filename - 3) != '/')
					break;
				if (pattern_type == -1)
					break; /* Must not contain pattern */
				contains_pattern = true;
				in_repetition = true;
				continue;
			case '}':   /* "\}/" */
				if (*filename != '/')
					break;
				if (!in_repetition)
					break;
				in_repetition = false;
				continue;
			case '0':   /* "\ooo" */
			case '1':
			case '2':
			case '3':
				d = *filename++;
				if (d < '0' || d > '7')
					break;
				e = *filename++;
				if (e < '0' || e > '7')
					break;
				c = ccs_make_byte(c, d, e);
				if (c && (c <= ' ' || c >= 127))
					continue; /* pattern is not \000 */
			}
			goto out;
		} else if (in_repetition && c == '/') {
			goto out;
		} else if (c <= ' ' || c >= 127) {
			goto out;
		}
	}
	if (pattern_type == 1) { /* Must contain pattern */
		if (!contains_pattern)
			goto out;
	}
	if (in_repetition)
		goto out;
	return true;
 out:
	return false;
}

/**
 * ccs_is_correct_domain - Check whether the given domainname follows the naming rules.
 *
 * @domainname:   The domainname to check.
 *
 * Returns true if @domainname follows the naming rules, false otherwise.
 */
bool ccs_is_correct_domain(const unsigned char *domainname)
{
	unsigned char c;
	unsigned char d;
	unsigned char e;
	if (!domainname || strncmp(domainname, ROOT_NAME, ROOT_NAME_LEN))
		goto out;
	domainname += ROOT_NAME_LEN;
	if (!*domainname)
		return true;
	do {
		if (*domainname++ != ' ')
			goto out;
		if (*domainname++ != '/')
			goto out;
		while (1) {
			c = *domainname;
			if (!c || c == ' ')
				break;
			domainname++;
			if (c == '\\') {
				c = *domainname++;
				switch ((c)) {
				case '\\':  /* "\\" */
					continue;
				case '0':   /* "\ooo" */
				case '1':
				case '2':
				case '3':
					d = *domainname++;
					if (d < '0' || d > '7')
						break;
					e = *domainname++;
					if (e < '0' || e > '7')
						break;
					c = ccs_make_byte(c, d, e);
					if (c && (c <= ' ' || c >= 127))
						/* pattern is not \000 */
						continue;
				}
				goto out;
			} else if (c < ' ' || c >= 127) {
				goto out;
			}
		}
	} while (*domainname);
	return true;
 out:
	return false;
}

/**
 * ccs_is_domain_def - Check whether the given token can be a domainname.
 *
 * @buffer: The token to check.
 *
 * Returns true if @buffer possibly be a domainname, false otherwise.
 */
bool ccs_is_domain_def(const unsigned char *buffer)
{
	return !strncmp(buffer, ROOT_NAME, ROOT_NAME_LEN);
}

/**
 * ccs_find_domain - Find a domain by the given name.
 *
 * @domainname: The domainname to find.
 *
 * Returns pointer to "struct ccs_domain_info" if found, NULL otherwise.
 *
 * Caller holds ccs_read_lock().
 */
struct ccs_domain_info *ccs_find_domain(const char *domainname)
{
	struct ccs_domain_info *domain;
	struct ccs_path_info name;
	name.name = domainname;
	ccs_fill_path_info(&name);
	list_for_each_entry_rcu(domain, &ccs_domain_list, list) {
		if (!domain->is_deleted &&
		    !ccs_pathcmp(&name, domain->domainname))
			return domain;
	}
	return NULL;
}

/**
 * ccs_const_part_length - Evaluate the initial length without a pattern in a token.
 *
 * @filename: The string to evaluate.
 *
 * Returns the initial length without a pattern in @filename.
 */
static int ccs_const_part_length(const char *filename)
{
	char c;
	int len = 0;
	if (!filename)
		return 0;
	while (1) {
		c = *filename++;
		if (!c)
			break;
		if (c != '\\') {
			len++;
			continue;
		}
		c = *filename++;
		switch (c) {
		case '\\':  /* "\\" */
			len += 2;
			continue;
		case '0':   /* "\ooo" */
		case '1':
		case '2':
		case '3':
			c = *filename++;
			if (c < '0' || c > '7')
				break;
			c = *filename++;
			if (c < '0' || c > '7')
				break;
			len += 4;
			continue;
		}
		break;
	}
	return len;
}

/**
 * ccs_fill_path_info - Fill in "struct ccs_path_info" members.
 *
 * @ptr: Pointer to "struct ccs_path_info" to fill in.
 *
 * The caller sets "struct ccs_path_info"->name.
 */
void ccs_fill_path_info(struct ccs_path_info *ptr)
{
	const char *name = ptr->name;
	const int len = strlen(name);
	ptr->total_len = len;
	ptr->const_len = ccs_const_part_length(name);
	ptr->is_dir = len && (name[len - 1] == '/');
	ptr->is_patterned = (ptr->const_len < len);
	ptr->hash = full_name_hash(name, len);
}

/**
 * ccs_file_matches_pattern2 - Pattern matching without '/' character and "\-" pattern.
 *
 * @filename:     The start of string to check.
 * @filename_end: The end of string to check.
 * @pattern:      The start of pattern to compare.
 * @pattern_end:  The end of pattern to compare.
 *
 * Returns true if @filename matches @pattern, false otherwise.
 */
static bool ccs_file_matches_pattern2(const char *filename,
				      const char *filename_end,
				      const char *pattern,
				      const char *pattern_end)
{
	while (filename < filename_end && pattern < pattern_end) {
		char c;
		if (*pattern != '\\') {
			if (*filename++ != *pattern++)
				return false;
			continue;
		}
		c = *filename;
		pattern++;
		switch (*pattern) {
			int i;
			int j;
		case '?':
			if (c == '/') {
				return false;
			} else if (c == '\\') {
				if (filename[1] == '\\')
					filename++;
				else if (ccs_is_byte_range(filename + 1))
					filename += 3;
				else
					return false;
			}
			break;
		case '\\':
			if (c != '\\')
				return false;
			if (*++filename != '\\')
				return false;
			break;
		case '+':
			if (!ccs_is_decimal(c))
				return false;
			break;
		case 'x':
			if (!ccs_is_hexadecimal(c))
				return false;
			break;
		case 'a':
			if (!ccs_is_alphabet_char(c))
				return false;
			break;
		case '0':
		case '1':
		case '2':
		case '3':
			if (c == '\\' && ccs_is_byte_range(filename + 1)
			    && !strncmp(filename + 1, pattern, 3)) {
				filename += 3;
				pattern += 2;
				break;
			}
			return false; /* Not matched. */
		case '*':
		case '@':
			for (i = 0; i <= filename_end - filename; i++) {
				if (ccs_file_matches_pattern2(filename + i,
							      filename_end,
							      pattern + 1,
							      pattern_end))
					return true;
				c = filename[i];
				if (c == '.' && *pattern == '@')
					break;
				if (c != '\\')
					continue;
				if (filename[i + 1] == '\\')
					i++;
				else if (ccs_is_byte_range(filename + i + 1))
					i += 3;
				else
					break; /* Bad pattern. */
			}
			return false; /* Not matched. */
		default:
			j = 0;
			c = *pattern;
			if (c == '$') {
				while (ccs_is_decimal(filename[j]))
					j++;
			} else if (c == 'X') {
				while (ccs_is_hexadecimal(filename[j]))
					j++;
			} else if (c == 'A') {
				while (ccs_is_alphabet_char(filename[j]))
					j++;
			}
			for (i = 1; i <= j; i++) {
				if (ccs_file_matches_pattern2(filename + i,
							      filename_end,
							      pattern + 1,
							      pattern_end))
					return true;
			}
			return false; /* Not matched or bad pattern. */
		}
		filename++;
		pattern++;
	}
	while (*pattern == '\\' &&
	       (*(pattern + 1) == '*' || *(pattern + 1) == '@'))
		pattern += 2;
	return filename == filename_end && pattern == pattern_end;
}

/**
 * ccs_file_matches_pattern - Pattern matching without '/' character.
 *
 * @filename:     The start of string to check.
 * @filename_end: The end of string to check.
 * @pattern:      The start of pattern to compare.
 * @pattern_end:  The end of pattern to compare.
 *
 * Returns true if @filename matches @pattern, false otherwise.
 */
static bool ccs_file_matches_pattern(const char *filename,
				     const char *filename_end,
				     const char *pattern,
				     const char *pattern_end)
{
	const char *pattern_start = pattern;
	bool first = true;
	bool result;
	while (pattern < pattern_end - 1) {
		/* Split at "\-" pattern. */
		if (*pattern++ != '\\' || *pattern++ != '-')
			continue;
		result = ccs_file_matches_pattern2(filename, filename_end,
						   pattern_start, pattern - 2);
		if (first)
			result = !result;
		if (result)
			return false;
		first = false;
		pattern_start = pattern;
	}
	result = ccs_file_matches_pattern2(filename, filename_end,
					   pattern_start, pattern_end);
	return first ? result : !result;
}

/**
 * ccs_path_matches_pattern2 - Do pathname pattern matching.
 *
 * @f: The start of string to check.
 * @p: The start of pattern to compare.
 *
 * Returns true if @f matches @p, false otherwise.
 */
static bool ccs_path_matches_pattern2(const char *f, const char *p)
{
	const char *f_delimiter;
	const char *p_delimiter;
	while (*f && *p) {
		f_delimiter = strchr(f, '/');
		if (!f_delimiter)
			f_delimiter = f + strlen(f);
		p_delimiter = strchr(p, '/');
		if (!p_delimiter)
			p_delimiter = p + strlen(p);
		if (*p == '\\' && *(p + 1) == '{')
			goto recursive;
		if (!ccs_file_matches_pattern(f, f_delimiter, p, p_delimiter))
			return false;
		f = f_delimiter;
		if (*f)
			f++;
		p = p_delimiter;
		if (*p)
			p++;
	}
	/* Ignore trailing "\*" and "\@" in @pattern. */
	while (*p == '\\' &&
	       (*(p + 1) == '*' || *(p + 1) == '@'))
		p += 2;
	return !*f && !*p;
 recursive:
	/*
	 * The "\{" pattern is permitted only after '/' character.
	 * This guarantees that below "*(p - 1)" is safe.
	 * Also, the "\}" pattern is permitted only before '/' character
	 * so that "\{" + "\}" pair will not break the "\-" operator.
	 */
	if (*(p - 1) != '/' || p_delimiter <= p + 3 || *p_delimiter != '/' ||
	    *(p_delimiter - 1) != '}' || *(p_delimiter - 2) != '\\')
		return false; /* Bad pattern. */
	do {
		/* Compare current component with pattern. */
		if (!ccs_file_matches_pattern(f, f_delimiter, p + 2,
					      p_delimiter - 2))
			break;
		/* Proceed to next component. */
		f = f_delimiter;
		if (!*f)
			break;
		f++;
		/* Continue comparison. */
		if (ccs_path_matches_pattern2(f, p_delimiter + 1))
			return true;
		f_delimiter = strchr(f, '/');
	} while (f_delimiter);
	return false; /* Not matched. */
}

/**
 * ccs_path_matches_pattern - Check whether the given filename matches the given pattern.
 *
 * @filename: The filename to check.
 * @pattern:  The pattern to compare.
 *
 * Returns true if matches, false otherwise.
 *
 * The following patterns are available.
 *   \\     \ itself.
 *   \ooo   Octal representation of a byte.
 *   \*     Zero or more repetitions of characters other than '/'.
 *   \@     Zero or more repetitions of characters other than '/' or '.'.
 *   \?     1 byte character other than '/'.
 *   \$     One or more repetitions of decimal digits.
 *   \+     1 decimal digit.
 *   \X     One or more repetitions of hexadecimal digits.
 *   \x     1 hexadecimal digit.
 *   \A     One or more repetitions of alphabet characters.
 *   \a     1 alphabet character.
 *
 *   \-     Subtraction operator.
 *
 *   /\{dir\}/   '/' + 'One or more repetitions of dir/' (e.g. /dir/ /dir/dir/
 *               /dir/dir/dir/ ).
 */
bool ccs_path_matches_pattern(const struct ccs_path_info *filename,
			      const struct ccs_path_info *pattern)
{
	const char *f = filename->name;
	const char *p = pattern->name;
	const int len = pattern->const_len;
	/* If @pattern doesn't contain pattern, I can use strcmp(). */
	if (!pattern->is_patterned)
		return !ccs_pathcmp(filename, pattern);
	/* Don't compare directory and non-directory. */
	if (filename->is_dir != pattern->is_dir)
		return false;
	/* Compare the initial length without patterns. */
	if (strncmp(f, p, len))
		return false;
	f += len;
	p += len;
	return ccs_path_matches_pattern2(f, p);
}

/**
 * ccs_get_exe - Get ccs_realpath() of current process.
 *
 * Returns the ccs_realpath() of current process on success, NULL otherwise.
 *
 * This function uses kzalloc(), so the caller must kfree()
 * if this function didn't return NULL.
 */
const char *ccs_get_exe(void)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	const char *cp = NULL;
	if (!mm)
		return NULL;
	down_read(&mm->mmap_sem);
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
			struct path path = { vma->vm_file->f_vfsmnt,
					     vma->vm_file->f_dentry };
			cp = ccs_realpath_from_path(&path);
#else
			cp = ccs_realpath_from_path(&vma->vm_file->f_path);
#endif
			break;
		}
	}
	up_read(&mm->mmap_sem);
	return cp;
}

/**
 * ccs_get_audit - Get audit mode.
 *
 * @profile:    Profile number.
 * @index:      Index number of functionality.
 * @is_granted: True if granted log, false otherwise.
 *
 * Returns mode.
 */
bool ccs_get_audit(const u8 profile, const u8 index, const bool is_granted)
{
	u8 mode;
	const u8 category = ccs_index2category[index] + CCS_MAX_MAC_INDEX
		+ CCS_MAX_CAPABILITY_INDEX;
	if (!ccs_policy_loaded)
		return false;
	mode = ccs_profile(profile)->config[index];
	if (mode == CCS_CONFIG_USE_DEFAULT)
		mode = ccs_profile(profile)->config[category];
	if (mode == CCS_CONFIG_USE_DEFAULT)
		mode = ccs_profile(profile)->default_config;
	if (is_granted)
		return mode & CCS_CONFIG_WANT_GRANT_LOG;
	return mode & CCS_CONFIG_WANT_REJECT_LOG;
}

/**
 * ccs_get_mode - Get MAC mode.
 *
 * @profile: Profile number.
 * @index:   Index number of functionality.
 *
 * Returns mode.
 */
int ccs_get_mode(const u8 profile, const u8 index)
{
	u8 mode;
	const u8 category = ccs_index2category[index] + CCS_MAX_MAC_INDEX
		+ CCS_MAX_CAPABILITY_INDEX;
	if (!ccs_policy_loaded)
		return CCS_CONFIG_DISABLED;
	mode = ccs_profile(profile)->config[index];
	if (mode == CCS_CONFIG_USE_DEFAULT)
		mode = ccs_profile(profile)->config[category];
	if (mode == CCS_CONFIG_USE_DEFAULT)
		mode = ccs_profile(profile)->default_config;
	return mode & 3;
}

/**
 * ccs_init_request_info - Initialize "struct ccs_request_info" members.
 *
 * @r:      Pointer to "struct ccs_request_info" to initialize.
 * @index:  Index number of functionality.
 *
 * Returns mode.
 */
int ccs_init_request_info(struct ccs_request_info *r, const u8 index)
{
	const u8 profile = ccs_current_domain()->profile;
	memset(r, 0, sizeof(*r));
	r->profile = profile;
	r->type = index;
	r->mode = ccs_get_mode(profile, index);
	return r->mode;
}

/**
 * ccs_last_word - Get last component of a line.
 *
 * @line: A line.
 *
 * Returns the last word of a line.
 */
const char *ccs_last_word(const char *name)
{
	const char *cp = strrchr(name, ' ');
	if (cp)
		return cp + 1;
	return name;
}

/**
 * ccs_warn_log - Print warning or error message on console.
 *
 * @r:   Pointer to "struct ccs_request_info".
 * @fmt: The printf()'s format string, followed by parameters.
 */
void ccs_warn_log(struct ccs_request_info *r, const char *fmt, ...)
{
	int len = PAGE_SIZE;
	va_list args;
	char *buffer;
	const struct ccs_domain_info * const domain = ccs_current_domain();
	const struct ccs_profile *profile = ccs_profile(domain->profile);
	switch (r->mode) {
	case CCS_CONFIG_ENFORCING:
		if (!profile->enforcing->enforcing_verbose)
			return;
		break;
	case CCS_CONFIG_PERMISSIVE:
		if (!profile->permissive->permissive_verbose)
			return;
		break;
	case CCS_CONFIG_LEARNING:
		if (!profile->learning->learning_verbose)
			return;
		break;
	}
	while (1) {
		int len2;
		buffer = kmalloc(len, CCS_GFP_FLAGS);
		if (!buffer)
			return;
		va_start(args, fmt);
		len2 = vsnprintf(buffer, len - 1, fmt, args);
		va_end(args);
		if (len2 <= len - 1) {
			buffer[len2] = '\0';
			break;
		}
		len = len2 + 1;
		kfree(buffer);
	}
	printk(KERN_WARNING "%s: Access %s denied for %s\n",
	       r->mode == CCS_CONFIG_ENFORCING ? "ERROR" : "WARNING", buffer,
	       ccs_last_word(domain->domainname->name));
	kfree(buffer);
}

/**
 * ccs_domain_quota_ok - Check for domain's quota.
 *
 * @r: Pointer to "struct ccs_request_info".
 *
 * Returns true if the domain is not exceeded quota, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_domain_quota_ok(struct ccs_request_info *r)
{
	unsigned int count = 0;
	struct ccs_domain_info * const domain = ccs_current_domain();
	struct ccs_acl_info *ptr;
	if (r->mode != CCS_CONFIG_LEARNING)
		return false;
	if (!domain)
		return true;
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		if (ptr->is_deleted)
			continue;
		switch (ptr->type) {
			u16 perm;
			u8 i;
		case CCS_TYPE_PATH_ACL:
			perm = container_of(ptr, struct ccs_path_acl, head)->
				perm;
			for (i = 0; i < CCS_MAX_PATH_OPERATION; i++)
				if (perm & (1 << i))
					count++;
			if (perm & (1 << CCS_TYPE_READ_WRITE))
				count -= 2;
			break;
		case CCS_TYPE_PATH2_ACL:
			perm = container_of(ptr, struct ccs_path2_acl,
					    head)->perm;
			for (i = 0; i < CCS_MAX_PATH2_OPERATION; i++)
				if (perm & (1 << i))
					count++;
			break;
		case CCS_TYPE_EXECUTE_HANDLER:
		case CCS_TYPE_DENIED_EXECUTE_HANDLER:
			break;
		case CCS_TYPE_PATH_NUMBER_ACL:
			perm = container_of(ptr, struct ccs_path_number_acl,
					    head)->perm;
			for (i = 0; i < CCS_MAX_PATH_NUMBER_OPERATION; i++)
				if (perm & (1 << i))
					count++;
			break;
		case CCS_TYPE_PATH_NUMBER3_ACL:
			perm = container_of(ptr, struct ccs_path_number3_acl,
					    head)->perm;
			for (i = 0; i < CCS_MAX_PATH_NUMBER3_OPERATION; i++)
				if (perm & (1 << i))
					count++;
			break;
		case CCS_TYPE_IP_NETWORK_ACL:
			perm = container_of(ptr, struct ccs_ip_network_acl,
					    head)->perm;
			for (i = 0; i < CCS_MAX_NETWORK_OPERATION; i++)
				if (perm & (1 << i))
					count++;
			break;
		default:
			count++;
		}
	}
	if (count < ccs_profile(domain->profile)->learning->learning_max_entry)
		return true;
	if (!domain->quota_warned) {
		domain->quota_warned = true;
		ccs_write_audit_log(false, r, CCS_KEYWORD_QUOTA_EXCEEDED "\n");
		printk(KERN_WARNING "WARNING: "
		       "Domain '%s' has so many ACLs to hold. "
		       "Stopped learning mode.\n", domain->domainname->name);
	}
	return false;
}
