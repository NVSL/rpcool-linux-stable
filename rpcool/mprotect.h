
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

int rpcool_change_protection(unsigned long start, size_t len,
			     unsigned long prot);

#endif // _RPCOOL_MPROTECT_H