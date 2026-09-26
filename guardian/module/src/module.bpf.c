#include "../include/vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/mmap_file")
int guardian_mmap_file(struct file* file, unsigned long reqprot, unsigned long prot, unsigned long flags)
{
    return 0;
}

SEC("lsm/mmap_addr")
int guardian_mmap_addr(unsigned long addr)
{
    return 0;
}

SEC("lsm/file_mprotect")
int guardian_mprotect(struct vm_area_struct* vma, unsigned long reqprot, unsigned long prot)
{
    return 0;
}

SEC("lsm/bprm_check_security")
int guardian_execve(struct linux_binprm* bprm)
{
    return 0;
}