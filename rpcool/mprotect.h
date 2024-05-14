
#ifndef _RPCOOL_MPROTECT_H
#define _RPCOOL_MPROTECT_H

#include <asm/mmu_context.h>
#include <asm/tlbflush.h>
#include <asm/tlb.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/mm_types.h>
#include <linux/mman.h>
#include <linux/mmap_lock.h>
#include <linux/hugetlb.h>
#include <linux/security.h>

struct vm_area_struct *rpcool_change_protection(unsigned long start, size_t len,
						unsigned long prot);

struct vm_area_struct *rpcool_change_protection_vma(struct vm_area_struct *vma,
						    unsigned long prot);

struct vm_area_struct *
rpcool_change_protection_vma_all(struct vm_area_struct **vma_array,
				 size_t vma_array_size, unsigned long prot);

void log_vma_info(const char *str, struct vm_area_struct *vma);

#endif // _RPCOOL_MPROTECT_H