#include "../include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <linux/errno.h>

char LICENSE[] SEC("license") = "GPL";

// MMAP_FILE

SEC("lsm/mmap_file")
int guardian_mmap_file(struct file* file, unsigned long reqprot, unsigned long prot, unsigned long flags)
{
    return 0;
}

// MMAP_ADDR

SEC("lsm/mmap_addr")
int guardian_mmap_addr(unsigned long addr)
{
    return 0;
}

// MPROTECT HOOK

struct page_key 
{
    __u64 mm;
    __u64 page_addr;   // page-aligned virtual address
};

struct 
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct page_key);
    __type(value, __u8);
} write_history SEC(".maps");

#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define MAX_PAGES_PER_REQUEST 64

static __always_inline void mark_range_written(struct mm_struct* mm, unsigned long start, unsigned long end)
{
    unsigned long addr = start & ~(PAGE_SIZE - 1);
    __u8 one = 1;

    for (int i = 0; i < MAX_PAGES_PER_REQUEST; i++) 
    {
        if (addr >= end) break;

        struct page_key key = { .mm = (__u64)mm, .page_addr = addr };
        bpf_map_update_elem(&write_history, &key, &one, BPF_ANY);

        addr += PAGE_SIZE;
    }
}

static __always_inline bool any_page_ever_written(struct mm_struct* mm, unsigned long start, unsigned long end)
{
    unsigned long addr = start & ~(PAGE_SIZE - 1);

    for (int i = 0; i < MAX_PAGES_PER_REQUEST; i++) 
    {
        if (addr >= end) break;

        struct page_key key = { .mm = (__u64)mm, .page_addr = addr };
        if (bpf_map_lookup_elem(&write_history, &key)) return true;

        addr += PAGE_SIZE;
    }

    return false;
}

#ifndef PROT_READ
#define PROT_READ   0x1
#endif
#ifndef PROT_WRITE
#define PROT_WRITE  0x2
#endif
#ifndef PROT_EXEC
#define PROT_EXEC   0x4
#endif

#ifndef VM_READ
#define VM_READ     0x00000001
#endif
#ifndef VM_WRITE
#define VM_WRITE    0x00000002
#endif
#ifndef VM_EXEC
#define VM_EXEC     0x00000004
#endif
#ifndef VM_SHARED
#define VM_SHARED   0x00000008
#endif

SEC("lsm/file_mprotect")
int guardian_mprotect(struct vm_area_struct* vma, unsigned long reqprot, unsigned long prot)
{
    // Wants to write, sure but annotate
    bool wants_write = prot & PROT_WRITE;
    if (wants_write) mark_range_written(vma->vm_mm, vma->vm_start, vma->vm_end);

    // Doesn't want EXEC, checks done
    bool wants_exec = prot & PROT_EXEC;
    if (!wants_exec) return 0;

    // Wants Exec but is shared, it is NO
    bool is_shared = vma->vm_flags & VM_SHARED; // VM_SHARED
    if (wants_exec && is_shared)
    {
        bpf_printk("guardian: deny exec on MAP_SHARED region"); 
        return -EPERM;
    } 

    // Wants exec, check if the process ever requested for write permissions
    if (any_page_ever_written(vma->vm_mm, vma->vm_start, vma->vm_end)) 
    {
        bpf_printk("guardian: deny exec, region was written before");
        return -EPERM;
    }

    return 0;
}

// EXECVE

#define MAX_BINS 64

__u64 whitelisted_bins[MAX_BINS];
__u32 whitelisted_bins_count;

static __always_inline int is_whitelisted(__u64* whitelist, __u32 count, __u64 ino)
{
    for (int i = 0; i < MAX_BINS; i++)
    {
        if (i >= count) break;
        if (whitelist[i] == ino) return 1;
    }

    return 0;
}

SEC("lsm/bprm_check_security")
int guardian_execve(struct linux_binprm* bprm)
{
    if (is_whitelisted(whitelisted_bins, whitelisted_bins_count, bprm->file->f_inode->i_ino))
    {
        bpf_printk("EXECUTION ALLOWED FOR %s (%llu)\n", &bprm->filename, bprm->file->f_inode->i_ino);
        return 0;
    }

    bpf_printk("EXECUTION BLOCKED FOR %s (%llu)\n", bprm->filename, bprm->file->f_inode->i_ino);
    return -EPERM;
}