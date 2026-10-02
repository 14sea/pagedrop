/* 
 * pagedrop - dump all executable pages of packed processes.
 * 
 * Copyright (C) 2021  Matteo Giordano
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define pr_fmt(fmt) "pagedrop: " fmt

#if defined(PB_ARCH_ARM64) || defined(CONFIG_ARM64)
#define PB_ARM64 1
#elif defined(PB_ARCH_X86_64) || defined(CONFIG_X86_64)
#define PB_X86_64 1
#endif

#include <linux/ftrace.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/kprobes.h>
#include <linux/init.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/limits.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/mmap_lock.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>

#include <asm/traps.h>
#if defined(PB_X86_64)
#include <asm/trap_pf.h>
#elif defined(PB_ARM64)
#include <asm/esr.h>
#endif

#include <uapi/asm-generic/mman-common.h>

#if !defined(PB_X86_64) && !defined(PB_ARM64)
#error Currently only x86_64 and arm64 are supported
#endif

#if defined(PB_ARM64) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
#error arm64 pagedrop requires Linux >= 5.10
#endif

#if defined(PB_ARM64)
#define PB_HOOK_KPROBE 1
#elif defined(PB_X86_64)
#define PB_HOOK_FTRACE 1
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
#define mmap_read_lock_killable(mm) down_read_killable(&(mm)->mmap_sem)
#define mmap_read_unlock(mm) up_read(&(mm)->mmap_sem)
#endif

static char *path;
module_param(path, charp, 0000);
MODULE_PARM_DESC(path, "Path/Name of the target process");

static LIST_HEAD(marea_list);
static DEFINE_MUTEX(marea_lock);
static unsigned long epoch_counter;

struct pb_tgid {
	struct list_head list;
	pid_t tgid;
};

static LIST_HEAD(tgid_list);
static DEFINE_SPINLOCK(tgid_lock);

struct marea {
	struct list_head list;
	unsigned long addr;
	unsigned long prot;
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
#define pb_access_ok(addr, size) access_ok(VERIFY_READ, (addr), (size))
#else
#define pb_access_ok(addr, size) access_ok((addr), (size))
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
static unsigned long lookup_name(const char *name)
{
	struct kprobe kp = {
		.symbol_name = name
	};
	unsigned long retval;

	if (register_kprobe(&kp) < 0)
		return 0;
	retval = (unsigned long)kp.addr;
	unregister_kprobe(&kp);
	return retval;
}
#else
static unsigned long lookup_name(const char *name)
{
	return kallsyms_lookup_name(name);
}
#endif

#if defined(PB_HOOK_FTRACE) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
#define ftrace_regs pt_regs

static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs)
{
	return fregs;
}
#endif

#define USE_FENTRY_OFFSET 0

#if defined(PB_HOOK_FTRACE)
struct ftrace_hook {
	const char *name;
	void *function;
	void *original;
	unsigned long address;
	struct ftrace_ops ops;
};
#endif

static bool pb_tgid_has(pid_t tgid)
{
	struct pb_tgid *t;
	bool found = false;

	if (tgid <= 0)
		return false;
	spin_lock(&tgid_lock);
	list_for_each_entry(t, &tgid_list, list) {
		if (t->tgid == tgid) {
			found = true;
			break;
		}
	}
	spin_unlock(&tgid_lock);
	return found;
}

static void pb_tgid_add(pid_t tgid)
{
	struct pb_tgid *t, *n;

	if (tgid <= 0)
		return;
	n = kmalloc(sizeof(*n), GFP_KERNEL);
	if (!n)
		return;
	n->tgid = tgid;
	INIT_LIST_HEAD(&n->list);
	spin_lock(&tgid_lock);
	list_for_each_entry(t, &tgid_list, list) {
		if (t->tgid == tgid) {
			spin_unlock(&tgid_lock);
			kfree(n);
			return;
		}
	}
	list_add(&n->list, &tgid_list);
	spin_unlock(&tgid_lock);
}

static void pb_tgid_del(pid_t tgid)
{
	struct pb_tgid *t, *tmp;

	spin_lock(&tgid_lock);
	list_for_each_entry_safe(t, tmp, &tgid_list, list) {
		if (t->tgid != tgid)
			continue;
		list_del(&t->list);
		kfree(t);
	}
	spin_unlock(&tgid_lock);
}

static void pb_tgid_clear(void)
{
	struct pb_tgid *t, *tmp;

	spin_lock(&tgid_lock);
	list_for_each_entry_safe(t, tmp, &tgid_list, list) {
		list_del(&t->list);
		kfree(t);
	}
	spin_unlock(&tgid_lock);
}

static bool pb_parent_tracked(void)
{
	struct task_struct *parent;
	pid_t tgid = 0;

	rcu_read_lock();
	parent = rcu_dereference(current->real_parent);
	if (parent)
		tgid = parent->tgid;
	rcu_read_unlock();
	return tgid > 0 && pb_tgid_has(tgid);
}

static bool pb_is_target(void)
{
	pid_t tgid;

	if (!path || !path[0])
		return false;
	tgid = current->tgid;
	if (pb_tgid_has(tgid))
		return true;
	if (pb_parent_tracked() || strstr(current->comm, path)) {
		pb_tgid_add(tgid);
		return true;
	}
	return false;
}

static bool prot_has_wx(unsigned long prot)
{
	return (prot & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC);
}

static bool prot_has_x_only(unsigned long prot)
{
	return (prot & PROT_EXEC) && !(prot & PROT_WRITE);
}

static unsigned long pb_arg(const struct pt_regs *regs, int n)
{
#if defined(PB_ARM64)
	if (n < 0 || n > 5)
		return 0;
	return regs->regs[n];
#else
	switch (n) {
	case 0:
		return regs->di;
	case 1:
		return regs->si;
	case 2:
		return regs->dx;
	case 3:
		return regs->r10;
	case 4:
		return regs->r8;
	case 5:
		return regs->r9;
	default:
		return 0;
	}
#endif
}

static void pb_set_arg(struct pt_regs *regs, int n, unsigned long val)
{
#if defined(PB_ARM64)
	if (n >= 0 && n <= 5)
		regs->regs[n] = val;
#else
	switch (n) {
	case 0:
		regs->di = val;
		break;
	case 1:
		regs->si = val;
		break;
	case 2:
		regs->dx = val;
		break;
	case 3:
		regs->r10 = val;
		break;
	default:
		break;
	}
#endif
}

static int pb_page_count(unsigned long len)
{
	if (!len)
		return 0;
	return (len + PAGE_SIZE - 1) / PAGE_SIZE;
}

static struct marea *search_page(unsigned long addr_given)
{
	struct marea *result;

	list_for_each_entry(result, &marea_list, list) {
		unsigned long start_addr = result->addr;
		unsigned long end_addr = start_addr + PAGE_SIZE - 1;

		if (addr_given >= start_addr && addr_given <= end_addr)
			return result;
	}
	return NULL;
}

static struct marea *new_marea(unsigned long addr, unsigned long prot)
{
	struct marea *new_m;

	new_m = kmalloc(sizeof(*new_m), GFP_KERNEL);
	if (!new_m)
		return NULL;
	new_m->addr = addr;
	new_m->prot = prot;
	INIT_LIST_HEAD(&new_m->list);
	return new_m;
}

static void track_pages(unsigned long addr, int n_pages, unsigned long prot)
{
	int i;

	mutex_lock(&marea_lock);
	for (i = 0; i < n_pages; i++) {
		struct marea *entry;
		struct marea *fresh;
		unsigned long page = addr + (i * PAGE_SIZE);
		int replaced = 0;

		list_for_each_entry(entry, &marea_list, list) {
			if (entry->addr != page)
				continue;
			fresh = new_marea(page, prot);
			if (!fresh)
				goto out;
			list_replace(&entry->list, &fresh->list);
			kfree(entry);
			replaced = 1;
			break;
		}
		if (replaced)
			continue;
		fresh = new_marea(page, prot);
		if (!fresh)
			break;
		list_add(&fresh->list, &marea_list);
	}
out:
	mutex_unlock(&marea_lock);
}

static void untrack_pages(unsigned long addr, int n_pages)
{
	int i;

	mutex_lock(&marea_lock);
	for (i = 0; i < n_pages; i++) {
		struct marea *entry, *tmp;
		unsigned long page = addr + (i * PAGE_SIZE);

		list_for_each_entry_safe(entry, tmp, &marea_list, list) {
			if (entry->addr != page)
				continue;
			list_del(&entry->list);
			kfree(entry);
		}
	}
	mutex_unlock(&marea_lock);
}

static void clear_tracked_locked(void)
{
	struct marea *entry, *tmp;

	list_for_each_entry_safe(entry, tmp, &marea_list, list) {
		list_del(&entry->list);
		kfree(entry);
	}
}

static void clear_tracked(void)
{
	mutex_lock(&marea_lock);
	clear_tracked_locked();
	mutex_unlock(&marea_lock);
}

static bool pb_take_page(unsigned long addr, unsigned long *page_addr, unsigned long *prot)
{
	struct marea *page;
	bool found = false;

	mutex_lock(&marea_lock);
	page = search_page(addr);
	if (page) {
		*page_addr = page->addr;
		*prot = page->prot;
		found = true;
	}
	mutex_unlock(&marea_lock);
	return found;
}

static int dump_to_file(unsigned long user_addr, size_t size)
{
	struct file *dest;
	char file_path[64];
	void *kbuf;
	loff_t pos = 0;
	ssize_t written;
	unsigned long left;

	if (!size || !pb_access_ok((void __user *)user_addr, size))
		return -EFAULT;

	kbuf = kvmalloc(size, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	left = copy_from_user(kbuf, (void __user *)user_addr, size);
	if (left) {
		pr_warn("copy_from_user %lx left %lu\n", user_addr, left);
		kvfree(kbuf);
		return -EFAULT;
	}

	snprintf(file_path, sizeof(file_path), "/tmp/%lx_%lu", user_addr, epoch_counter);
	epoch_counter++;

	dest = filp_open(file_path, O_CREAT | O_WRONLY | O_TRUNC | O_LARGEFILE, 0644);
	if (IS_ERR(dest)) {
		pr_warn("filp_open %s: %ld\n", file_path, PTR_ERR(dest));
		kvfree(kbuf);
		return PTR_ERR(dest);
	}

	written = kernel_write(dest, kbuf, size, &pos);
	if (written < 0 || (size_t)written != size)
		pr_warn("kernel_write %s: %zd\n", file_path, written);
	filp_close(dest, NULL);
	kvfree(kbuf);
	return written < 0 ? written : 0;
}

static void dump_pages(unsigned long addr, int n_pages)
{
	int i;

	for (i = 0; i < n_pages; i++)
		dump_to_file(addr + (i * PAGE_SIZE), PAGE_SIZE);
}

#if defined(PB_HOOK_FTRACE)
static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = lookup_name(hook->name);
	if (!hook->address) {
		pr_err("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long *)hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long *)hook->original) = hook->address;
#endif
	return 0;
}

static void pb_set_ip(struct ftrace_regs *fregs, unsigned long ip)
{
#if defined(ftrace_regs_set_instruction_pointer)
	ftrace_regs_set_instruction_pointer(fregs, ip);
#else
	struct pt_regs *regs = ftrace_get_regs(fregs);

	if (regs)
		instruction_pointer_set(regs, ip);
#endif
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
	pb_set_ip(fregs, (unsigned long)hook->function);
#else
	if (!within_module(parent_ip, THIS_MODULE))
		pb_set_ip(fregs, (unsigned long)hook->function);
#endif
}

static unsigned long pb_ftrace_flags(void)
{
	unsigned long flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
	flags |= FTRACE_OPS_FL_RECURSION_SAFE;
#endif
	return flags;
}

static int fh_install_hook(struct ftrace_hook *hook)
{
	int err;

	err = fh_resolve_hook_address(hook);
	if (err)
		return err;

	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = pb_ftrace_flags();

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		pr_err("ftrace_set_filter_ip(%s) failed: %d\n", hook->name, err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_err("register_ftrace_function(%s) failed: %d\n", hook->name, err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	pr_info("hooked %s @ %lx\n", hook->name, hook->address);
	return 0;
}

static void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err)
		pr_err("unregister_ftrace_function(%s) failed: %d\n", hook->name, err);

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err)
		pr_err("ftrace_set_filter_ip(%s) remove failed: %d\n", hook->name, err);
}

static int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;

	for (i = 0; i < count; i++) {
		err = fh_install_hook(&hooks[i]);
		if (err)
			goto error;
	}
	return 0;

error:
	while (i != 0)
		fh_remove_hook(&hooks[--i]);
	return err;
}

static void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}
#endif

#if defined(PB_ARM64) || (defined(PB_X86_64) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0))
#define PTREGS_SYSCALL_STUBS 1
#endif

#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

static void pb_handle_protect(struct pt_regs *regs)
{
	unsigned long addr = pb_arg(regs, 0);
	unsigned long len = pb_arg(regs, 1);
	unsigned long prot = pb_arg(regs, 2);
	int n_pages = pb_page_count(len);

	if (prot_has_wx(prot)) {
		track_pages(addr, n_pages, prot);
		pb_set_arg(regs, 2, prot & ~PROT_WRITE);
	} else if (prot_has_x_only(prot)) {
		dump_pages(addr, n_pages);
	} else {
		untrack_pages(addr, n_pages);
	}
}

static asmlinkage long (*real_sys_mprotect)(struct pt_regs *regs);

static asmlinkage long fh_sys_mprotect(struct pt_regs *regs)
{
	if (!pb_is_target())
		return real_sys_mprotect(regs);
	pb_handle_protect(regs);
	return real_sys_mprotect(regs);
}

static asmlinkage long (*real_sys_pkey_mprotect)(struct pt_regs *regs);

static asmlinkage long fh_sys_pkey_mprotect(struct pt_regs *regs)
{
	if (!pb_is_target())
		return real_sys_pkey_mprotect(regs);
	pb_handle_protect(regs);
	return real_sys_pkey_mprotect(regs);
}

static bool pb_page_exec(unsigned long addr)
{
	struct vm_area_struct *vma;
	bool exec = false;

	if (!current->mm)
		return false;
	if (mmap_read_lock_killable(current->mm))
		return false;
	vma = find_vma(current->mm, addr);
	if (vma && vma->vm_start <= addr && (vma->vm_flags & VM_EXEC))
		exec = true;
	mmap_read_unlock(current->mm);
	return exec;
}

static void pb_note_mremap(unsigned long old, unsigned long old_len,
			   unsigned long new, unsigned long new_len)
{
	unsigned long old_pages = pb_page_count(old_len);
	unsigned long new_pages = pb_page_count(new_len);
	unsigned long i;

	old &= PAGE_MASK;
	new &= PAGE_MASK;
	for (i = 0; i < old_pages; i++) {
		struct marea *entry;
		unsigned long from = old + i * PAGE_SIZE;

		mutex_lock(&marea_lock);
		entry = search_page(from);
		if (entry) {
			if (i < new_pages)
				entry->addr = new + i * PAGE_SIZE;
			else {
				list_del(&entry->list);
				kfree(entry);
			}
		}
		mutex_unlock(&marea_lock);
		if (i < new_pages && pb_page_exec(new + i * PAGE_SIZE))
			dump_to_file(new + i * PAGE_SIZE, PAGE_SIZE);
	}
}

static asmlinkage long (*real_sys_mremap)(struct pt_regs *regs);

static asmlinkage long fh_sys_mremap(struct pt_regs *regs)
{
	unsigned long old = pb_arg(regs, 0);
	unsigned long old_len = pb_arg(regs, 1);
	unsigned long new_len = pb_arg(regs, 2);
	long ret;

	if (!pb_is_target())
		return real_sys_mremap(regs);
	ret = real_sys_mremap(regs);
	if (ret < 0)
		return ret;
	pb_note_mremap(old, old_len, (unsigned long)ret, new_len);
	return ret;
}

static asmlinkage unsigned long (*real_vm_mmap_pgoff)(struct file *file,
		unsigned long addr, unsigned long len, unsigned long prot,
		unsigned long flag, unsigned long pgoff);

static asmlinkage unsigned long fh_vm_mmap_pgoff(struct file *file,
		unsigned long addr, unsigned long len, unsigned long prot,
		unsigned long flag, unsigned long pgoff)
{
	unsigned long ret;
	unsigned long intended;
	int n_pages;

	if (!pb_is_target())
		return real_vm_mmap_pgoff(file, addr, len, prot, flag, pgoff);

	n_pages = pb_page_count(len);

	if (prot_has_wx(prot)) {
		intended = prot;
		if (!file)
			flag |= MAP_POPULATE;
		ret = real_vm_mmap_pgoff(file, addr, len, prot & ~PROT_WRITE,
					 flag, pgoff);
		if (!IS_ERR_VALUE(ret))
			track_pages(ret, n_pages, intended);
		return ret;
	}

	ret = real_vm_mmap_pgoff(file, addr, len, prot, flag, pgoff);
	if (IS_ERR_VALUE(ret))
		return ret;

	if (prot_has_x_only(prot))
		dump_pages(ret, n_pages);
	else
		untrack_pages(ret, n_pages);

	return ret;
}

static asmlinkage long (*real_force_sig_fault)(int sig, int code, void __user *addr);

static bool pb_fault_is_write(void)
{
#if defined(PB_ARM64)
	unsigned long esr = current->thread.fault_code;

	if ((esr & ESR_ELx_FSC) == ESR_ELx_FSC_MTE)
		return false;
	return ESR_ELx_EC(esr) == ESR_ELx_EC_DABT_LOW && (esr & ESR_ELx_WNR);
#else
	return current->thread.error_code & X86_PF_WRITE;
#endif
}

static bool pb_fault_is_instr(void)
{
#if defined(PB_ARM64)
	unsigned long esr = current->thread.fault_code;

	if ((esr & ESR_ELx_FSC) == ESR_ELx_FSC_MTE)
		return false;
	return ESR_ELx_EC(esr) == ESR_ELx_EC_IABT_LOW;
#else
	return current->thread.error_code & X86_PF_INSTR;
#endif
}

static asmlinkage int fh_force_sig_fault(int sig, int code, void __user *addr)
{
	struct pt_regs *regs;
	unsigned long address = (unsigned long)addr;

#if defined(PB_ARM64)
	address = untagged_addr(address);
#endif
	unsigned long page_addr, new_prot;

	if (!pb_is_target() || sig != SIGSEGV)
		return real_force_sig_fault(sig, code, addr);

	if (!pb_take_page(address, &page_addr, &new_prot))
		return real_force_sig_fault(sig, code, addr);

	regs = kzalloc(sizeof(*regs), GFP_KERNEL);
	if (!regs)
		return real_force_sig_fault(sig, code, addr);

	pb_set_arg(regs, 0, page_addr);
	pb_set_arg(regs, 1, PAGE_SIZE);

	if (pb_fault_is_write()) {
		new_prot &= ~PROT_EXEC;
		pb_set_arg(regs, 2, new_prot);
		real_sys_mprotect(regs);
		kfree(regs);
		return 0;
	}

	if (pb_fault_is_instr()) {
		dump_to_file(page_addr, PAGE_SIZE);
		new_prot &= ~PROT_WRITE;
		pb_set_arg(regs, 2, new_prot);
		real_sys_mprotect(regs);
		kfree(regs);
		return 0;
	}

	kfree(regs);
	return real_force_sig_fault(sig, code, addr);
}

static bool pb_name_matches(const char *name)
{
	return path && path[0] && name && name[0] && strstr(name, path);
}

static bool pb_user_path_matches(const char __user *uname)
{
	char *buf;
	long n;
	bool ok;

	if (!uname)
		return false;
	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return false;
	n = strncpy_from_user(buf, uname, PATH_MAX);
	if (n < 0) {
		kfree(buf);
		return false;
	}
	if (n == PATH_MAX)
		buf[PATH_MAX - 1] = '\0';
	ok = pb_name_matches(buf);
	kfree(buf);
	return ok;
}

static bool pb_fd_path_matches(int fd)
{
	struct file *f;
	char *buf, *p;
	bool ok = false;

	if (fd < 0)
		return false;
	f = fget(fd);
	if (!f)
		return false;
	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf) {
		fput(f);
		return false;
	}
	p = d_path(&f->f_path, buf, PATH_MAX);
	if (!IS_ERR(p))
		ok = pb_name_matches(p);
	kfree(buf);
	fput(f);
	return ok;
}

static void pb_move_tracked(struct list_head *saved)
{
	mutex_lock(&marea_lock);
	list_splice_init(&marea_list, saved);
	mutex_unlock(&marea_lock);
}

static void pb_free_list(struct list_head *head)
{
	struct marea *entry, *tmp;

	list_for_each_entry_safe(entry, tmp, head, list) {
		list_del(&entry->list);
		kfree(entry);
	}
}

static long pb_finish_exec(struct list_head *saved, bool matched, long ret)
{
	if (!matched)
		return ret;
	if (ret == 0) {
		pb_free_list(saved);
		return ret;
	}
	mutex_lock(&marea_lock);
	clear_tracked_locked();
	list_splice_init(saved, &marea_list);
	mutex_unlock(&marea_lock);
	return ret;
}

static long pb_do_exec(bool matched, long (*real)(struct pt_regs *), struct pt_regs *regs)
{
	bool added = false;
	long ret;
	LIST_HEAD(saved);

	if (matched) {
		added = !pb_tgid_has(current->tgid);
		pb_tgid_add(current->tgid);
		pb_move_tracked(&saved);
	}
	ret = real(regs);
	if (matched && ret != 0 && added)
		pb_tgid_del(current->tgid);
	return pb_finish_exec(&saved, matched, ret);
}

static asmlinkage long (*real_sys_execve)(struct pt_regs *regs);

static asmlinkage long fh_sys_execve(struct pt_regs *regs)
{
	bool matched;

	matched = pb_user_path_matches((const char __user *)pb_arg(regs, 0));
	return pb_do_exec(matched, real_sys_execve, regs);
}

static asmlinkage long (*real_sys_execveat)(struct pt_regs *regs);

static asmlinkage long fh_sys_execveat(struct pt_regs *regs)
{
	bool matched;
	int fd = (int)pb_arg(regs, 0);
	int flags = (int)pb_arg(regs, 4);

	matched = pb_user_path_matches((const char __user *)pb_arg(regs, 1));
	if (!matched && (flags & AT_EMPTY_PATH))
		matched = pb_fd_path_matches(fd);
	return pb_do_exec(matched, real_sys_execveat, regs);
}

static void pb_note_child(long child, unsigned long flags, bool has_flags)
{
	if (child <= 0 || !pb_tgid_has(current->tgid))
		return;
	if (has_flags && (flags & CLONE_THREAD))
		return;
	pb_tgid_add((pid_t)child);
}

static asmlinkage long (*real_sys_fork)(struct pt_regs *regs);
static asmlinkage long (*real_sys_vfork)(struct pt_regs *regs);
static asmlinkage long (*real_sys_clone)(struct pt_regs *regs);
static asmlinkage long (*real_sys_clone3)(struct pt_regs *regs);

static asmlinkage long fh_sys_fork(struct pt_regs *regs)
{
	long ret = real_sys_fork(regs);

	pb_note_child(ret, 0, false);
	return ret;
}

static asmlinkage long fh_sys_vfork(struct pt_regs *regs)
{
	long ret = real_sys_vfork(regs);

	pb_note_child(ret, 0, false);
	return ret;
}

static asmlinkage long fh_sys_clone(struct pt_regs *regs)
{
	long ret = real_sys_clone(regs);

	pb_note_child(ret, pb_arg(regs, 0), true);
	return ret;
}

static asmlinkage long fh_sys_clone3(struct pt_regs *regs)
{
	u64 flags = 0;
	long ret;

	if (copy_from_user(&flags, (void __user *)pb_arg(regs, 0), sizeof(flags)))
		flags = 0;
	ret = real_sys_clone3(regs);
	pb_note_child(ret, flags, true);
	return ret;
}

static void (*real_do_exit)(long code);

static void fh_do_exit(long code)
{
	if (current->signal && atomic_read(&current->signal->live) <= 1)
		pb_tgid_del(current->tgid);
	real_do_exit(code);
	BUG();
}

#if defined(PB_ARM64)
#define SYSCALL_NAME(name) ("__arm64_" name)
#elif defined(PTREGS_SYSCALL_STUBS)
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif

#define HOOK(_name, _function, _original)	\
	{					\
		.name = SYSCALL_NAME(_name),	\
		.function = (_function),	\
		.original = (_original),	\
	}

#define HOOK_NOSYS(_name, _function, _original)	\
	{					\
		.name = _name,			\
		.function = (_function),	\
		.original = (_original),	\
	}

#if defined(PB_HOOK_FTRACE)
static struct ftrace_hook demo_hooks[] = {
	HOOK("sys_mprotect", fh_sys_mprotect, &real_sys_mprotect),
	HOOK("sys_pkey_mprotect", fh_sys_pkey_mprotect, &real_sys_pkey_mprotect),
	HOOK("sys_mremap", fh_sys_mremap, &real_sys_mremap),
	HOOK_NOSYS("vm_mmap_pgoff", fh_vm_mmap_pgoff, &real_vm_mmap_pgoff),
	HOOK("sys_execve", fh_sys_execve, &real_sys_execve),
	HOOK("sys_execveat", fh_sys_execveat, &real_sys_execveat),
	HOOK("sys_fork", fh_sys_fork, &real_sys_fork),
	HOOK("sys_vfork", fh_sys_vfork, &real_sys_vfork),
	HOOK("sys_clone", fh_sys_clone, &real_sys_clone),
	HOOK("sys_clone3", fh_sys_clone3, &real_sys_clone3),
	HOOK_NOSYS("do_exit", fh_do_exit, &real_do_exit),
	HOOK_NOSYS("force_sig_fault", fh_force_sig_fault, &real_force_sig_fault),
};

static int pb_install_hooks(void)
{
	return fh_install_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
}

static void pb_remove_hooks(void)
{
	fh_remove_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
}
#elif defined(PB_HOOK_KPROBE)
struct pb_arm_hook {
	const char *name;
	void *function;
	void *original;
	struct kprobe kp;
};

static int pb_arm_pre(struct kprobe *kp, struct pt_regs *regs)
{
	struct pb_arm_hook *hook = container_of(kp, struct pb_arm_hook, kp);

	if (within_module(regs->regs[30], THIS_MODULE))
		return 0;
	instruction_pointer_set(regs, (unsigned long)hook->function);
	return 1;
}
NOKPROBE_SYMBOL(pb_arm_pre);

static struct pb_arm_hook arm_hooks[] = {
	{ SYSCALL_NAME("sys_mprotect"), fh_sys_mprotect, &real_sys_mprotect },
	{ SYSCALL_NAME("sys_pkey_mprotect"), fh_sys_pkey_mprotect, &real_sys_pkey_mprotect },
	{ SYSCALL_NAME("sys_mremap"), fh_sys_mremap, &real_sys_mremap },
	{ "vm_mmap_pgoff", fh_vm_mmap_pgoff, &real_vm_mmap_pgoff },
	{ SYSCALL_NAME("sys_execve"), fh_sys_execve, &real_sys_execve },
	{ SYSCALL_NAME("sys_execveat"), fh_sys_execveat, &real_sys_execveat },
	{ SYSCALL_NAME("sys_fork"), fh_sys_fork, &real_sys_fork },
	{ SYSCALL_NAME("sys_vfork"), fh_sys_vfork, &real_sys_vfork },
	{ SYSCALL_NAME("sys_clone"), fh_sys_clone, &real_sys_clone },
	{ SYSCALL_NAME("sys_clone3"), fh_sys_clone3, &real_sys_clone3 },
	{ "do_exit", fh_do_exit, &real_do_exit },
	{ "force_sig_fault", fh_force_sig_fault, &real_force_sig_fault },
};

static int pb_install_hooks(void)
{
	size_t i;
	int err;

	for (i = 0; i < ARRAY_SIZE(arm_hooks); i++) {
		unsigned long addr = lookup_name(arm_hooks[i].name);

		if (!addr) {
			pr_err("unresolved symbol: %s\n", arm_hooks[i].name);
			err = -ENOENT;
			goto unwind;
		}
		*(unsigned long *)arm_hooks[i].original = addr;
		arm_hooks[i].kp.symbol_name = arm_hooks[i].name;
		arm_hooks[i].kp.pre_handler = pb_arm_pre;
		err = register_kprobe(&arm_hooks[i].kp);
		if (err) {
			pr_err("register_kprobe(%s) failed: %d\n", arm_hooks[i].name, err);
			goto unwind;
		}
		pr_info("hooked %s @ %lx\n", arm_hooks[i].name, addr);
	}
	return 0;

unwind:
	while (i--)
		unregister_kprobe(&arm_hooks[i].kp);
	return err;
}

static void pb_remove_hooks(void)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(arm_hooks); i++) {
		if (!arm_hooks[i].kp.addr)
			continue;
		unregister_kprobe(&arm_hooks[i].kp);
	}
}
#endif

static int fh_init(void)
{
	int err;

	if (!path || !path[0]) {
		pr_err("missing path= module parameter\n");
		return -EINVAL;
	}

	err = pb_install_hooks();
	if (err)
		return err;

	pr_info("loaded, watching comm/%s\n", path);
	return 0;
}
module_init(fh_init);

static void fh_exit(void)
{
	pb_remove_hooks();
	clear_tracked();
	pb_tgid_clear();
	pr_info("unloaded\n");
}
module_exit(fh_exit);

MODULE_DESCRIPTION("pagedrop - dump all executable pages of packed processes.");
MODULE_AUTHOR("Matteo Giordano <matteo.giordano@protonmail.com>");
MODULE_LICENSE("GPL");
