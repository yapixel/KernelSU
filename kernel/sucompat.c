#include <linux/dcache.h>
#include <linux/security.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/ptrace.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task_stack.h>
#else
#include <linux/sched.h>
#endif

#include "objsec.h"
#include "allowlist.h"
#include "klog.h" // IWYU pragma: keep
#include "ksud.h"
#include "kernel_compat.h"

#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"

extern void escape_to_root();

static bool ksu_sucompat_non_kp __read_mostly = true;

static void __user *userspace_stack_buffer(const void *d, size_t len)
{
	/* To avoid having to mmap a page in userspace, just write below the stack
   * pointer. */
	char __user *p = (void __user *)current_user_stack_pointer() - len;

	return copy_to_user(p, d, len) ? NULL : p;
}

static char __user *sh_user_path(void)
{
	static const char sh_path[] = "/system/bin/sh";

	return userspace_stack_buffer(sh_path, sizeof(sh_path));
}

static char __user *ksud_user_path(void)
{
	static const char ksud_path[] = KSUD_PATH;

	return userspace_stack_buffer(ksud_path, sizeof(ksud_path));
}

// every little bit helps here
__attribute__((hot, no_stack_protector))
static __always_inline bool is_su_allowed(const void *ptr_to_check)
{
	barrier();
	if (!ksu_sucompat_non_kp)
		return false;

	if (likely(!ksu_is_allow_uid(current_uid().val)))
		return false;

	if (unlikely(!ptr_to_check))
		return false;

	return true;
}

static int ksu_sucompat_user_common(const char __user **filename_user,
				const char *syscall_name,
				const bool escalate)
{
	const char su[] = SU_PATH;

	char path[sizeof(su)]; // sizeof includes nullterm already!
	if (ksu_copy_from_user_retry(path, *filename_user, sizeof(path)))
		return 0;

	path[sizeof(path) - 1] = '\0';

	if (memcmp(path, su, sizeof(su)))
		return 0;

	if (escalate) {
		pr_info("%s su found\n", syscall_name);
		*filename_user = ksud_user_path();
		escape_to_root(); // escalate !!
	} else {
		pr_info("%s su->sh!\n", syscall_name);
		*filename_user = sh_user_path();
	}

	return 0;
}

// sys_faccessat
int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode,
			 int *__unused_flags)
{
	if (!is_su_allowed((const void *)filename_user))
		return 0;

	return ksu_sucompat_user_common(filename_user, "faccessat", false);
}

// sys_newfstatat, sys_fstat64
int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
	if (!is_su_allowed((const void *)filename_user))
		return 0;

	return ksu_sucompat_user_common(filename_user, "newfstatat", false);
}

// sys_execve, compat_sys_execve
int ksu_handle_execve_sucompat(int *fd, const char __user **filename_user,
			       void *__never_use_argv, void *__never_use_envp,
			       int *__never_use_flags)
{
	if (!is_su_allowed((const void *)filename_user))
		return 0;

	return ksu_sucompat_user_common(filename_user, "sys_execve", true);
}

// getname_flags on fs/namei.c, this hooks ALL fs-related syscalls.
// NOT RECOMMENDED for daily use. mostly for debugging purposes.
int ksu_getname_flags_user(const char __user **filename_user, int flags)
{
	if (!is_su_allowed((const void *)filename_user))
		return 0;

	// sys_execve always calls getname, which sets flags = 0 on getname_flags
	// we can use it to deduce if caller is likely execve
	return ksu_sucompat_user_common(filename_user, "getname_flags", !!!flags);
}

static int ksu_sucompat_kernel_common(void *filename_ptr, const char *function_name, bool escalate)
{

	if (likely(memcmp(filename_ptr, SU_PATH, sizeof(SU_PATH))))
		return 0;

	if (escalate) {
		pr_info("%s su found\n", function_name);
		memcpy(filename_ptr, KSUD_PATH, sizeof(KSUD_PATH));
		escape_to_root();
	} else {
		pr_info("%s su->sh\n", function_name);
		memcpy(filename_ptr, SH_PATH, sizeof(SH_PATH));
	}
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
// for do_execveat_common / do_execve_common on >= 3.14
// take note: struct filename **filename
int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
				 void *__never_use_argv, void *__never_use_envp,
				 int *__never_use_flags)
{
	if (!is_su_allowed((const void *)filename_ptr))
		return 0;

	// struct filename *filename = *filename_ptr;
	// return ksu_do_execveat_common((void *)filename->name, "do_execveat_common");
	// nvm this, just inline

	return ksu_sucompat_kernel_common((void *)(*filename_ptr)->name, "do_execveat_common", true);
}

int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,
			void *envp, int *flags)
{
	return ksu_handle_execveat_sucompat(fd, filename_ptr, argv, envp, flags);
}
#else
// for do_execve_common on < 3.14
// take note: char **filename
int ksu_legacy_execve_sucompat(const char **filename_ptr,
				 void *__never_use_argv,
				 void *__never_use_envp)
{
	if (!is_su_allowed((const void *)filename_ptr))
		return 0;

	return ksu_sucompat_kernel_common((void *)*filename_ptr, "do_execve_common", true);
}
#endif

// getname_flags on fs/namei.c, this hooks ALL fs-related syscalls.
// put the hook right after usercopy
// NOT RECOMMENDED for daily use. mostly for debugging purposes.
int ksu_getname_flags_kernel(char **kname, int flags)
{
	if (!is_su_allowed((const void *)kname))
		return 0;

	return ksu_sucompat_kernel_common((void *)*kname, "getname_flags", !!!flags);
}

// dummified
int ksu_handle_devpts(struct inode *inode)
{
	return 0;
}

int __ksu_handle_devpts(struct inode *inode)
{
	barrier();
	if (!ksu_sucompat_non_kp)
		return 0;

	if (!current->mm) {
		return 0;
	}

	uid_t uid = current_uid().val;
	if (uid % 100000 < 10000) {
		// not untrusted_app, ignore it
		return 0;
	}

	if (likely(!ksu_is_allow_uid(uid)))
		return 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
	struct inode_security_struct *sec = selinux_inode(inode);
#else
	struct inode_security_struct *sec = (struct inode_security_struct *)inode->i_security;
#endif
	if (ksu_devpts_sid && sec)
		sec->sid = ksu_devpts_sid;

	return 0;
}

// sucompat: permited process can execute 'su' to gain root access.
void ksu_sucompat_init()
{
	ksu_sucompat_non_kp = true;
	pr_info("ksu_sucompat_init: hooks enabled: exec, faccessat, stat, devpts\n");
}

void ksu_sucompat_exit()
{
	ksu_sucompat_non_kp = false;
	pr_info("ksu_sucompat_exit: hooks disabled: exec, faccessat, stat, devpts\n");
}
