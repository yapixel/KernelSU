// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 \xx
 *
 * This file is a downstream extension and NOT affiliated, endorsed by,
 * or maintained by the official KernelSU developers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#ifndef __KSU_H_HOSTSREDIRECT
#define __KSU_H_HOSTSREDIRECT

static bool ksu_kernel_umount_enabled __read_mostly;

static inline int ksu_handle_openat(const char __user *filename, int flags)
{
	const char __user *uptr = (const char __user *)untagged_addr((void *)filename);

	char hf[] = "/system/etc/hosts";
	char buf[sizeof(hf)];

	if (copy_from_user_retry(buf, uptr, strlen(hf)))
		return -EFAULT;

	if (!!__builtin_strcmp(buf, hf))
		return -1;

	// pr_info("%s: intercepting %s for comm: %s pid: %d\n", __func__, hf, current->comm, current->pid);

	const struct cred *saved = override_creds(ksu_cred);
	struct file *filp = filp_open("/data/adb/hosts", O_RDONLY, 0);
	revert_creds(saved);

	if (IS_ERR(filp))
		return -EBADF;

	if (force_o_largefile())
		flags |= O_LARGEFILE;

	int fd = get_unused_fd_flags(flags);
	if (fd < 0) {
		fput(filp);
		return fd;
	}

	fd_install(fd, filp);
	// pr_info("%s: fd: %d\n", __func__, fd);

	return fd;
}

#define __AARCH64_openat 56

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
static syscall_fn_t aarch64_openat __read_mostly = NULL;
asmlinkage long hook_aarch64_openat(const struct pt_regs *regs)
{
	const char __user *filename = (const char __user *)regs->regs[1];
	int flags = (int)regs->regs[2];

	if (likely(test_thread_flag(TIF_KSU_UNMOUNTABLE)))
		goto orig_fn;

	if (likely(!ksu_module_mounted))
		goto orig_fn;

	if (likely(!ksu_kernel_umount_enabled))
		goto orig_fn;

	int fd = ksu_handle_openat(filename, flags);
	if (fd > 0)
		return fd;

orig_fn:
	return __arm64_sys_openat(regs);
}
#else
static void *aarch64_openat __read_mostly = NULL;
asmlinkage long hook_aarch64_openat(int dfd, const char __user *filename, int flags, umode_t mode)
{
	if (likely(test_thread_flag(TIF_KSU_UNMOUNTABLE)))
		goto orig_fn;

	if (likely(!ksu_module_mounted))
		goto orig_fn;

	if (likely(!ksu_kernel_umount_enabled))
		goto orig_fn;

	int fd = ksu_handle_openat(filename, flags);
	if (fd > 0)
		return fd;

orig_fn:
	return sys_openat(dfd, filename, flags, mode);
}
#endif

static __init void ksu_hostsredirect()
{
	pr_info("ksu_hostsredirect: hooking sys_openat \n");
	read_and_replace_syscall((void *)&aarch64_openat, __AARCH64_openat, (void *)hook_aarch64_openat, (void *)sys_call_table);
}


static void ksu_hostsredirect_unhook()
{
	// we unhook at boot complete if /data/adb/hosts does not exist
	struct path kpath;
	if (!!kern_path("/data/adb/hosts", 0, &kpath))
		goto unhook;

	path_put(&kpath);
	pr_info("ksu_hostsredirect: /data/adb/hosts found! keeping sys_openat hook\n");
	return;

unhook:
	pr_info("ksu_hostsredirect: /data/adb/hosts not found! unhook sys_openat \n");
	read_and_replace_syscall((void *)&aarch64_openat, __AARCH64_openat, (void *)hook_aarch64_openat, (void *)sys_call_table);
	return;
}


#endif // __KSU_H_HOSTSREDIRECT
