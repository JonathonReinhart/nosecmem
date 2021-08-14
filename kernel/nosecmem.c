#define MODNAME         "nosecmem"
#define pr_fmt(fmt)     "%s: " fmt, MODNAME

#include <linux/fdtable.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/version.h>
#include <linux/sched/mm.h>
#include <uapi/linux/magic.h>

MODULE_AUTHOR("Jonathon Reinhart <jonathon.reinhart@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Demonstrate reading memfd_secret() files from the kernel");
MODULE_VERSION("0.0.0");

static bool is_secretmem_file(struct file *file)
{
    return file && file_inode(file)->i_sb->s_magic == SECRETMEM_MAGIC;
}

static size_t file_size(struct file *file)
{
    return file_inode(file)->i_size;
}

static int handle_secretmem_file(struct file *file)
{
    struct inode *inode = file_inode(file);
    const unsigned long len = inode->i_size;
    void *map = NULL;
    int ret = 0;

    map = (void *) vm_mmap(file, 0, len, PROT_READ, MAP_SHARED, 0);
    if (IS_ERR(map)) {
        long err = PTR_ERR(map);
        pr_err("vm_mmap() failed: %ld\n", err);
        ret = -ENOMEM;
        goto out;
    }

    print_hex_dump(KERN_INFO, MODNAME ":   ", DUMP_PREFIX_OFFSET,
                   16, 1, map, len, true);

out:
    if (map)
        vm_munmap((unsigned long)map, len);
    return ret;
}

/* task_lock() and rcu_read_lock() must be held */
static struct file *get_file_by_fd(struct files_struct *files, unsigned int fd)
{
    /**
     * fcheck_files() was renamed to files_lookup_fd_rcu() in commit
     * v5.10-rc1-10-gf36c29432741
     *
     * fcheck_files() is present in Debian Bullseye kernel 5.10.0-8 headers.
     */
#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 10, 0)
    return files_lookup_fd_rcu(files, fd);
#else
    return fcheck_files(files, fd);
#endif
}

static void handle_task_files(struct task_struct *task)
{
    struct files_struct *files = task->files;
    unsigned int fd;

    /* See proc_readfd_common() */
    /* requires task_lock() or atomic_inc(&files->count) */
    if (!files)
        return;

    for (fd = 0; fd < files_fdtable(files)->max_fds; fd++) {
        struct file *file;

        file = get_file_by_fd(files, fd);

        if (!is_secretmem_file(file))
            continue;

        pr_info("Found secretmem file size %ld at fd %d\n",
                file_size(file), fd);
        handle_secretmem_file(file);
    }
}

/**
 * Like the unexported mm_access(), except:
 * - Does not take task_lock() (assumes it is already held)
 */
static struct mm_struct *__mm_access(struct task_struct *task)
{
    struct mm_struct *mm;
    int err;

    err = down_read_killable(&task->signal->exec_update_lock);
    if (err)
        return ERR_PTR(err);

    /* Don't call get_task_mm(); it takes task_lock() */
    mm = task->mm;
    if (mm) {
        if (task->flags & PF_KTHREAD)
            mm = NULL;
        else
            mmget(mm);
    }

    up_read(&task->signal->exec_update_lock);

    return mm;
}

static struct vm_area_struct *first_vma(struct mm_struct *mm)
{
    /* TODO: Another way to get first VMA? */
    return find_vma(mm, 0);
}

static void handle_task_mm(struct task_struct *task)
{
    /* See proc_pid_maps_op */
    struct mm_struct *mm;
    struct vm_area_struct *vma;

    mm = __mm_access(task);
    if (IS_ERR(mm)) {
        pr_err("__mm_access() failed: %ld\n", PTR_ERR(mm));
        goto out;
    }

    if (mmap_read_lock_killable(mm)) {
        pr_err("mmap_read_lock_killable() failed\n");
        goto out_mmput;
    }

    for (vma = first_vma(mm); vma; vma = vma->vm_next) {
        struct file* file = vma->vm_file;

        if (!is_secretmem_file(file))
            continue;

        pr_info("Found secretmem file size %ld at vma 0x%lX-0x%lX\n",
                file_size(file), vma->vm_start, vma->vm_end);
        handle_secretmem_file(file);
    }


    mmap_read_unlock(mm);
out_mmput:
    mmput(mm);
out:
    return;
}

static void handle_task(struct task_struct *task)
{
    task_lock(task);

    pr_info("Inspecting task %d [%s]\n", task->pid, task->comm);

    /* TODO: get task files and mm and release task lock */

    handle_task_files(task);
    handle_task_mm(task);

    task_unlock(task);
}

static int handle_pid(struct pid *pid)
{
    struct task_struct *task;

    task = get_pid_task(pid, PIDTYPE_PID);
    if (!task)
        return -ESRCH;

    rcu_read_lock();
    handle_task(task);
    rcu_read_unlock();

    put_task_struct(task);
    return 0;
}

static int handle_pid_nr(u32 pid_nr)
{
    struct pid *pid = NULL;
    int rc;

    pid = find_get_pid(pid_nr);
    if (!pid)
        return -ESRCH;

    rc = handle_pid(pid);

    put_pid(pid);
    return rc;
}

static ssize_t nosecmem_write(struct file *file, const char __user *buf,
                              size_t count, loff_t *ppos)
{
    u32 pid_nr;
    int rc;

    if (*ppos != 0) {
        /* No partial writes. */
        return -EINVAL;
    }

    rc = kstrtou32_from_user(buf, count, 10, &pid_nr);
    if (rc < 0)
        return rc;

    rc = handle_pid_nr(pid_nr);
    if (rc < 0)
        return rc;

    return count;
}

static const struct proc_ops nosecmem_ops = {
	.proc_write = nosecmem_write,
	.proc_lseek = default_llseek,
};

#define PROCNAME    MODNAME

static struct proc_dir_entry *procent;

static int __init kmod_init(void)
{
    procent = proc_create(PROCNAME, S_IWUGO, NULL, &nosecmem_ops);
    if (!procent) {
        pr_err("Failed to register proc interface\n");
        return -ENOMEM;
    }

	pr_info("Write a PID to /proc/"PROCNAME" to see all of the "
            "\"secret memory\" areas for that process.\n");
    return 0;
}

static void __exit kmod_exit(void)
{
    proc_remove(procent);
    procent = NULL;
}

module_init(kmod_init);
module_exit(kmod_exit);
