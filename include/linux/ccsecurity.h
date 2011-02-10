/*
 * include/linux/ccsecurity.h
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.7.2+   2010/06/04
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#ifndef _LINUX_CCSECURITY_H
#define _LINUX_CCSECURITY_H

#include <linux/version.h>

#ifndef __user
#define __user
#endif

struct nameidata;
struct path;
struct dentry;
struct vfsmount;
struct inode;
struct linux_binprm;
struct pt_regs;
struct file;
struct ctl_table;
struct socket;
struct sockaddr;
struct sock;
struct sk_buff;
struct msghdr;
struct file_system_type;
struct pid_namespace;
int search_binary_handler(struct linux_binprm *bprm, struct pt_regs *regs);

#ifdef CONFIG_CCSECURITY

/* For exporting variables and functions. */
struct ccsecurity_exports {
	void (*load_policy) (const char *filename);
	void (*put_filesystem) (struct file_system_type *fs);
	asmlinkage long (*sys_getppid) (void);
	asmlinkage long (*sys_getpid) (void);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
	spinlock_t *vfsmount_lock;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
	struct task_struct *(*find_task_by_vpid) (pid_t pid);
	struct task_struct *(*find_task_by_pid_ns) (pid_t pid,
						    struct pid_namespace *ns);
#endif
};

/* For doing access control. */
struct ccsecurity_operations {
	void (*check_profile) (void);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	int (*chroot_permission) (struct path *path);
	int (*pivot_root_permission) (struct path *old_path,
				      struct path *new_path);
	int (*may_mount) (struct path *path);
	int (*mount_permission) (char *dev_name, struct path *path, char *type,
				 unsigned long flags, void *data_page);
#else
	int (*chroot_permission) (struct nameidata *nd);
	int (*pivot_root_permission) (struct nameidata *old_nd,
				      struct nameidata *new_nd);
	int (*may_mount) (struct nameidata *nd);
	int (*mount_permission) (char *dev_name, struct nameidata *nd,
				 char *type, unsigned long flags,
				 void *data_page);
#endif
	int (*umount_permission) (struct vfsmount *mnt, int flags);
	_Bool (*lport_reserved) (const u16 port);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 34)
	void (*save_open_mode) (int mode);
	void (*clear_open_mode) (void);
#endif
	int (*ptrace_permission) (long request, long pid);
	int (*open_permission) (struct dentry *dentry, struct vfsmount *mnt,
				const int flag);
	int (*ioctl_permission) (struct file *filp, unsigned int cmd,
				 unsigned long arg);
	int (*parse_table) (int __user *name, int nlen, void __user *oldval,
			    void __user *newval, struct ctl_table *table);
	_Bool (*capable) (const u8 operation);
	int (*mknod_permission) (struct inode *dir, struct dentry *dentry,
				 struct vfsmount *mnt, unsigned int mode,
				 unsigned int dev);
	int (*mkdir_permission) (struct inode *dir, struct dentry *dentry,
				 struct vfsmount *mnt, unsigned int mode);
	int (*rmdir_permission) (struct inode *dir, struct dentry *dentry,
				 struct vfsmount *mnt);
	int (*unlink_permission) (struct inode *dir, struct dentry *dentry,
				  struct vfsmount *mnt);
	int (*symlink_permission) (struct inode *dir, struct dentry *dentry,
				   struct vfsmount *mnt, const char *from);
	int (*truncate_permission) (struct dentry *dentry,
				    struct vfsmount *mnt);
	int (*rename_permission) (struct inode *old_dir,
				  struct dentry *old_dentry,
				  struct inode *new_dir,
				  struct dentry *new_dentry,
				  struct vfsmount *mnt);
	int (*link_permission) (struct dentry *old_dentry,
				struct inode *new_dir,
				struct dentry *new_dentry,
				struct vfsmount *mnt);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	int (*open_exec_permission) (struct dentry *dentry,
				     struct vfsmount *mnt);
	int (*uselib_permission) (struct dentry *dentry, struct vfsmount *mnt);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
	int (*fcntl_permission) (struct file *file, unsigned int cmd,
				 unsigned long arg);
#else
	int (*rewrite_permission) (struct file *filp);
#endif
	int (*kill_permission) (pid_t pid, int sig);
	int (*tgkill_permission) (pid_t tgid, pid_t pid, int sig);
	int (*tkill_permission) (pid_t pid, int sig);
	int (*socket_create_permission) (int family, int type, int protocol);
	int (*socket_listen_permission) (struct socket *sock);
	int (*socket_connect_permission) (struct socket *sock,
					  struct sockaddr *addr, int addr_len);
	int (*socket_bind_permission) (struct socket *sock,
				       struct sockaddr *addr, int addr_len);
	int (*socket_accept_permission) (struct socket *sock,
					 struct sockaddr *addr);
	int (*socket_sendmsg_permission) (struct socket *sock,
					  struct msghdr *msg, int size);
	int (*socket_recvmsg_permission) (struct sock *sk, struct sk_buff *skb,
					  const unsigned int flags);
	int (*chown_permission) (struct dentry *dentry, struct vfsmount *mnt,
				 uid_t user, gid_t group);
	int (*chmod_permission) (struct dentry *dentry, struct vfsmount *mnt,
				 mode_t mode);
	int (*sigqueue_permission) (pid_t pid, int sig);
	int (*tgsigqueue_permission) (pid_t tgid, pid_t pid, int sig);
	int (*search_binary_handler) (struct linux_binprm *bprm,
				      struct pt_regs *regs);
	_Bool disabled;
};

extern const struct ccsecurity_exports ccsecurity_exports;
extern struct ccsecurity_operations ccsecurity_ops;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)

static inline int ccs_chroot_permission(struct path *path)
{
	return ccsecurity_ops.chroot_permission ?
		ccsecurity_ops.chroot_permission(path) : 0;
}

static inline int ccs_pivot_root_permission(struct path *old_path,
					    struct path *new_path)
{
	return ccsecurity_ops.pivot_root_permission ?
		ccsecurity_ops.pivot_root_permission(old_path, new_path) : 0;
}

static inline int ccs_may_mount(struct path *path)
{
	return ccsecurity_ops.may_mount ?
		ccsecurity_ops.may_mount(path) : 0;
}

static inline int ccs_mount_permission(char *dev_name, struct path *path,
				       char *type, unsigned long flags,
				       void *data_page)
{
	return ccsecurity_ops.mount_permission ?
		ccsecurity_ops.mount_permission(dev_name, path, type, flags,
						data_page) : 0;
}

#else

static inline int ccs_chroot_permission(struct nameidata *nd)
{
	return ccsecurity_ops.chroot_permission ?
		ccsecurity_ops.chroot_permission(nd) : 0;
}

static inline int ccs_pivot_root_permission(struct nameidata *old_nd,
					    struct nameidata *new_nd)
{
	return ccsecurity_ops.pivot_root_permission ?
		ccsecurity_ops.pivot_root_permission(old_nd, new_nd) : 0;
}

static inline int ccs_may_mount(struct nameidata *nd)
{
	return ccsecurity_ops.may_mount ? ccsecurity_ops.may_mount(nd) : 0;
}

static inline int ccs_mount_permission(char *dev_name, struct nameidata *nd,
				       char *type, unsigned long flags,
				       void *data_page)
{
	return ccsecurity_ops.mount_permission ?
		ccsecurity_ops.mount_permission(dev_name, nd, type, flags,
						data_page) : 0;
}
#endif

static inline int ccs_umount_permission(struct vfsmount *mnt, int flags)
{
	return ccsecurity_ops.umount_permission ?
		ccsecurity_ops.umount_permission(mnt, flags) : 0;
}

static inline _Bool ccs_lport_reserved(const u16 port)
{
	return ccsecurity_ops.lport_reserved ?
		ccsecurity_ops.lport_reserved(port) : 0;
}

static inline int ccs_ptrace_permission(long request, long pid)
{
	return ccsecurity_ops.ptrace_permission ?
		ccsecurity_ops.ptrace_permission(request, pid) : 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 34)
static inline void ccs_save_open_mode(int mode)
{
	if (ccsecurity_ops.save_open_mode)
		ccsecurity_ops.save_open_mode(mode);
}

static inline void ccs_clear_open_mode(void)
{
	if (ccsecurity_ops.clear_open_mode)
		ccsecurity_ops.clear_open_mode();
}
#endif

static inline int ccs_open_permission(struct dentry *dentry,
				      struct vfsmount *mnt, const int flag)
{
	return ccsecurity_ops.open_permission ?
		ccsecurity_ops.open_permission(dentry, mnt, flag) : 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
static inline int ccs_fcntl_permission(struct file *file, unsigned int cmd,
				       unsigned long arg)
{
	return ccsecurity_ops.fcntl_permission ?
		ccsecurity_ops.fcntl_permission(file, cmd, arg) : 0;
}
#else
static inline int ccs_rewrite_permission(struct file *filp)
{
	return ccsecurity_ops.rewrite_permission ?
		ccsecurity_ops.rewrite_permission(filp) : 0;
}
#endif

static inline int ccs_ioctl_permission(struct file *filp, unsigned int cmd,
				       unsigned long arg)
{
	return ccsecurity_ops.ioctl_permission ?
		ccsecurity_ops.ioctl_permission(filp, cmd, arg) : 0;
}

static inline int ccs_parse_table(int __user *name, int nlen,
				  void __user *oldval, void __user *newval,
				  struct ctl_table *table)
{
	return ccsecurity_ops.parse_table ?
		ccsecurity_ops.parse_table(name, nlen, oldval, newval, table) :
		0;
}

static inline _Bool ccs_capable(const u8 operation)
{
	return ccsecurity_ops.capable ? ccsecurity_ops.capable(operation) : 1;
}

static inline int ccs_mknod_permission(struct inode *dir,
				       struct dentry *dentry,
				       struct vfsmount *mnt, unsigned int mode,
				       unsigned int dev)
{
	return ccsecurity_ops.mknod_permission ?
		ccsecurity_ops.mknod_permission(dir, dentry, mnt, mode, dev) :
		0;
}

static inline int ccs_mkdir_permission(struct inode *dir,
				       struct dentry *dentry,
				       struct vfsmount *mnt, unsigned int mode)
{
	return ccsecurity_ops.mkdir_permission ?
		ccsecurity_ops.mkdir_permission(dir, dentry, mnt, mode) : 0;
}

static inline int ccs_rmdir_permission(struct inode *dir,
				       struct dentry *dentry,
				       struct vfsmount *mnt)
{
	return ccsecurity_ops.rmdir_permission ?
		ccsecurity_ops.rmdir_permission(dir, dentry, mnt) : 0;
}

static inline int ccs_unlink_permission(struct inode *dir,
					struct dentry *dentry,
					struct vfsmount *mnt)
{
	return ccsecurity_ops.unlink_permission ?
		ccsecurity_ops.unlink_permission(dir, dentry, mnt) : 0;
}

static inline int ccs_symlink_permission(struct inode *dir,
					 struct dentry *dentry,
					 struct vfsmount *mnt,
					 const char *from)
{
	return ccsecurity_ops.symlink_permission ?
		ccsecurity_ops.symlink_permission(dir, dentry, mnt, from) : 0;
}

static inline int ccs_truncate_permission(struct dentry *dentry,
					  struct vfsmount *mnt, loff_t length,
					  unsigned int time_attrs)
{
	return ccsecurity_ops.truncate_permission ?
		ccsecurity_ops.truncate_permission(dentry, mnt) : 0;
}

static inline int ccs_rename_permission(struct inode *old_dir,
					struct dentry *old_dentry,
					struct inode *new_dir,
					struct dentry *new_dentry,
					struct vfsmount *mnt)
{
	return ccsecurity_ops.rename_permission ?
		ccsecurity_ops.rename_permission(old_dir, old_dentry, new_dir,
						 new_dentry, mnt) : 0;
}

static inline int ccs_link_permission(struct dentry *old_dentry,
				      struct inode *new_dir,
				      struct dentry *new_dentry,
				      struct vfsmount *mnt)
{
	return ccsecurity_ops.link_permission ?
		ccsecurity_ops.link_permission(old_dentry, new_dir, new_dentry,
					       mnt) : 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
static inline int ccs_open_exec_permission(struct dentry *dentry,
					   struct vfsmount *mnt)
{
	return ccsecurity_ops.open_exec_permission ?
		ccsecurity_ops.open_exec_permission(dentry, mnt) : 0;
}

static inline int ccs_uselib_permission(struct dentry *dentry,
					struct vfsmount *mnt)
{
	return ccsecurity_ops.uselib_permission ?
		ccsecurity_ops.uselib_permission(dentry, mnt) : 0;
}
#endif

static inline int ccs_kill_permission(pid_t pid, int sig)
{
	return ccsecurity_ops.kill_permission ?
		ccsecurity_ops.kill_permission(pid, sig) : 0;
}

static inline int ccs_tgkill_permission(pid_t tgid, pid_t pid, int sig)
{
	return ccsecurity_ops.tgkill_permission ?
		ccsecurity_ops.tgkill_permission(tgid, pid, sig) : 0;
}

static inline int ccs_tkill_permission(pid_t pid, int sig)
{
	return ccsecurity_ops.tkill_permission ?
		ccsecurity_ops.tkill_permission(pid, sig) : 0;
}

static inline int ccs_socket_create_permission(int family, int type,
					       int protocol)
{
	return ccsecurity_ops.socket_create_permission ?
		ccsecurity_ops.socket_create_permission(family, type, protocol)
		: 0;
}

static inline int ccs_socket_listen_permission(struct socket *sock)
{
	return ccsecurity_ops.socket_listen_permission ?
		ccsecurity_ops.socket_listen_permission(sock) : 0;
}

static inline int ccs_socket_connect_permission(struct socket *sock,
						struct sockaddr *addr,
						int addr_len)
{
	return ccsecurity_ops.socket_connect_permission ?
		ccsecurity_ops.socket_connect_permission(sock, addr, addr_len)
		: 0;
}

static inline int ccs_socket_bind_permission(struct socket *sock,
					     struct sockaddr *addr,
					     int addr_len)
{
	return ccsecurity_ops.socket_bind_permission ?
		ccsecurity_ops.socket_bind_permission(sock, addr, addr_len) :
		0;
}

static inline int ccs_socket_accept_permission(struct socket *sock,
					       struct sockaddr *addr)
{
	return ccsecurity_ops.socket_accept_permission ?
		ccsecurity_ops.socket_accept_permission(sock, addr) : 0;
}

static inline int ccs_socket_sendmsg_permission(struct socket *sock,
						struct msghdr *msg,
						int size)
{
	return ccsecurity_ops.socket_sendmsg_permission ?
		ccsecurity_ops.socket_sendmsg_permission(sock, msg, size) : 0;
}

static inline int ccs_socket_recvmsg_permission(struct sock *sk,
						struct sk_buff *skb,
						const unsigned int flags)
{
	return ccsecurity_ops.socket_recvmsg_permission ?
		ccsecurity_ops.socket_recvmsg_permission(sk, skb, flags) : 0;
}

static inline int ccs_chown_permission(struct dentry *dentry,
				       struct vfsmount *mnt, uid_t user,
				       gid_t group)
{
	return ccsecurity_ops.chown_permission ?
		ccsecurity_ops.chown_permission(dentry, mnt, user, group) : 0;
}

static inline int ccs_chmod_permission(struct dentry *dentry,
				       struct vfsmount *mnt, mode_t mode)
{
	return ccsecurity_ops.chmod_permission ?
		ccsecurity_ops.chmod_permission(dentry, mnt, mode) : 0;
}

static inline int ccs_sigqueue_permission(pid_t pid, int sig)
{
	return ccsecurity_ops.sigqueue_permission ?
		ccsecurity_ops.sigqueue_permission(pid, sig) : 0;
}

static inline int ccs_tgsigqueue_permission(pid_t tgid, pid_t pid, int sig)
{
	return ccsecurity_ops.tgsigqueue_permission ?
		ccsecurity_ops.tgsigqueue_permission(tgid, pid, sig) : 0;
}

static inline int ccs_search_binary_handler(struct linux_binprm *bprm,
					    struct pt_regs *regs)
{
	return ccsecurity_ops.search_binary_handler(bprm, regs);
}

#else

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)

static inline int ccs_chroot_permission(struct path *path)
{
	return 0;
}

static inline int ccs_pivot_root_permission(struct path *old_path,
					    struct path *new_path)
{
	return 0;
}

static inline int ccs_may_mount(struct path *path)
{
	return 0;
}

static inline int ccs_mount_permission(char *dev_name, struct path *path,
				       char *type, unsigned long flags,
				       void *data_page)
{
	return 0;
}

#else

static inline int ccs_chroot_permission(struct nameidata *nd)
{
	return 0;
}

static inline int ccs_pivot_root_permission(struct nameidata *old_nd,
					    struct nameidata *new_nd)
{
	return 0;
}

static inline int ccs_may_mount(struct nameidata *nd)
{
	return 0;
}

static inline int ccs_mount_permission(char *dev_name, struct nameidata *nd,
				       char *type, unsigned long flags,
				       void *data_page)
{
	return 0;
}

#endif

static inline int ccs_umount_permission(struct vfsmount *mnt, int flags)
{
	return 0;
}

static inline _Bool ccs_lport_reserved(const u16 port)
{
	return 0;
}

static inline int ccs_ptrace_permission(long request, long pid)
{
	return 0;
}

static inline void ccs_save_open_mode(int mode)
{
}

static inline void ccs_clear_open_mode(void)
{
}

static inline int ccs_open_permission(struct dentry *dentry,
				      struct vfsmount *mnt, const int flag)
{
	return 0;
}

static inline int ccs_rewrite_permission(struct file *filp)
{
	return 0;
}

static inline int ccs_ioctl_permission(struct file *filp, unsigned int cmd,
				       unsigned long arg)
{
	return 0;
}

static inline int ccs_parse_table(int __user *name, int nlen,
				  void __user *oldval, void __user *newval,
				  struct ctl_table *table)
{
	return 0;
}

static inline _Bool ccs_capable(const u8 operation)
{
	return 1;
}

static inline int ccs_mknod_permission(struct inode *dir,
				       struct dentry *dentry,
				       struct vfsmount *mnt, unsigned int mode,
				       unsigned int dev)
{
	return 0;
}

static inline int ccs_mkdir_permission(struct inode *dir,
				       struct dentry *dentry,
				       struct vfsmount *mnt, unsigned int mode)
{
	return 0;
}

static inline int ccs_rmdir_permission(struct inode *dir,
				       struct dentry *dentry,
				       struct vfsmount *mnt)
{
	return 0;
}

static inline int ccs_unlink_permission(struct inode *dir,
					struct dentry *dentry,
					struct vfsmount *mnt)
{
	return 0;
}

static inline int ccs_symlink_permission(struct inode *dir,
					 struct dentry *dentry,
					 struct vfsmount *mnt,
					 const char *from)
{
	return 0;
}

static inline int ccs_truncate_permission(struct dentry *dentry,
					  struct vfsmount *mnt, loff_t length,
					  unsigned int time_attrs)
{
	return 0;
}

static inline int ccs_rename_permission(struct inode *old_dir,
					struct dentry *old_dentry,
					struct inode *new_dir,
					struct dentry *new_dentry,
					struct vfsmount *mnt)
{
	return 0;
}

static inline int ccs_link_permission(struct dentry *old_dentry,
				      struct inode *new_dir,
				      struct dentry *new_dentry,
				      struct vfsmount *mnt)
{
	return 0;
}

static inline int ccs_open_exec_permission(struct dentry *dentry,
					   struct vfsmount *mnt)
{
	return 0;
}

static inline int ccs_uselib_permission(struct dentry *dentry,
					struct vfsmount *mnt)
{
	return 0;
}

static inline int ccs_fcntl_permission(struct file *file, unsigned int cmd,
				       unsigned long arg)
{
	return 0;
}

static inline int ccs_kill_permission(pid_t pid, int sig)
{
	return 0;
}

static inline int ccs_tgkill_permission(pid_t tgid, pid_t pid, int sig)
{
	return 0;
}

static inline int ccs_tkill_permission(pid_t pid, int sig)
{
	return 0;
}

static inline int ccs_socket_create_permission(int family, int type,
					       int protocol)
{
	return 0;
}

static inline int ccs_socket_listen_permission(struct socket *sock)
{
	return 0;
}

static inline int ccs_socket_connect_permission(struct socket *sock,
						struct sockaddr *addr,
						int addr_len)
{
	return 0;
}

static inline int ccs_socket_bind_permission(struct socket *sock,
					     struct sockaddr *addr,
					     int addr_len)
{
	return 0;
}

static inline int ccs_socket_accept_permission(struct socket *sock,
					       struct sockaddr *addr)
{
	return 0;
}

static inline int ccs_socket_sendmsg_permission(struct socket *sock,
						struct msghdr *msg, int size)
{
	return 0;
}

static inline int ccs_socket_recvmsg_permission(struct sock *sk,
						struct sk_buff *skb,
						const unsigned int flags)
{
	return 0;
}

static inline int ccs_chown_permission(struct dentry *dentry,
				       struct vfsmount *mnt, uid_t user,
				       gid_t group)
{
	return 0;
}

static inline int ccs_chmod_permission(struct dentry *dentry,
				       struct vfsmount *mnt, mode_t mode)
{
	return 0;
}

static inline int ccs_sigqueue_permission(pid_t pid, int sig)
{
	return 0;
}

static inline int ccs_tgsigqueue_permission(pid_t tgid, pid_t pid, int sig)
{
	return 0;
}

static inline int ccs_search_binary_handler(struct linux_binprm *bprm,
					    struct pt_regs *regs)
{
	return search_binary_handler(bprm, regs);
}

#endif

/* Index numbers for Capability Controls. */
enum ccs_capability_acl_index {
	/* socket(PF_INET or PF_INET6, SOCK_STREAM, *)                 */
	CCS_INET_STREAM_SOCKET_CREATE,
	/* listen() for PF_INET or PF_INET6, SOCK_STREAM               */
	CCS_INET_STREAM_SOCKET_LISTEN,
	/* connect() for PF_INET or PF_INET6, SOCK_STREAM              */
	CCS_INET_STREAM_SOCKET_CONNECT,
	/* socket(PF_INET or PF_INET6, SOCK_DGRAM, *)                  */
	CCS_USE_INET_DGRAM_SOCKET,
	/* socket(PF_INET or PF_INET6, SOCK_RAW, *)                    */
	CCS_USE_INET_RAW_SOCKET,
	/* socket(PF_ROUTE, *, *)                                      */
	CCS_USE_ROUTE_SOCKET,
	/* socket(PF_PACKET, *, *)                                     */
	CCS_USE_PACKET_SOCKET,
	/* sys_mount()                                                 */
	CCS_SYS_MOUNT,
	/* sys_umount()                                                */
	CCS_SYS_UMOUNT,
	/* sys_reboot()                                                */
	CCS_SYS_REBOOT,
	/* sys_chroot()                                                */
	CCS_SYS_CHROOT,
	/* sys_kill(), sys_tkill(), sys_tgkill()                       */
	CCS_SYS_KILL,
	/* sys_vhangup()                                               */
	CCS_SYS_VHANGUP,
	/* do_settimeofday(), sys_adjtimex()                           */
	CCS_SYS_SETTIME,
	/* sys_nice(), sys_setpriority()                               */
	CCS_SYS_NICE,
	/* sys_sethostname(), sys_setdomainname()                      */
	CCS_SYS_SETHOSTNAME,
	/* sys_create_module(), sys_init_module(), sys_delete_module() */
	CCS_USE_KERNEL_MODULE,
	/* sys_mknod(S_IFIFO)                                          */
	CCS_CREATE_FIFO,
	/* sys_mknod(S_IFBLK)                                          */
	CCS_CREATE_BLOCK_DEV,
	/* sys_mknod(S_IFCHR)                                          */
	CCS_CREATE_CHAR_DEV,
	/* sys_mknod(S_IFSOCK)                                         */
	CCS_CREATE_UNIX_SOCKET,
	/* sys_link()                                                  */
	CCS_SYS_LINK,
	/* sys_symlink()                                               */
	CCS_SYS_SYMLINK,
	/* sys_rename()                                                */
	CCS_SYS_RENAME,
	/* sys_unlink()                                                */
	CCS_SYS_UNLINK,
	/* sys_chmod(), sys_fchmod()                                   */
	CCS_SYS_CHMOD,
	/* sys_chown(), sys_fchown(), sys_lchown()                     */
	CCS_SYS_CHOWN,
	/* sys_ioctl(), compat_sys_ioctl()                             */
	CCS_SYS_IOCTL,
	/* sys_kexec_load()                                            */
	CCS_SYS_KEXEC_LOAD,
	/* sys_pivot_root()                                            */
	CCS_SYS_PIVOT_ROOT,
	/* sys_ptrace()                                                */
	CCS_SYS_PTRACE,
	/* conceal mount                                               */
	CCS_CONCEAL_MOUNT,
	CCS_MAX_CAPABILITY_INDEX
};

#endif
