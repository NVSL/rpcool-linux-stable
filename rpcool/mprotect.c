#include "mprotect.h"
#include <linux/mm.h>

int rpcool_change_protection(unsigned long start, size_t len,
			     unsigned long prot)
{
	unsigned long nstart, end, tmp, reqprot;
	int error;
	struct vm_area_struct *vma, *prev;
	struct mmu_gather tlb;
	MA_STATE(mas, &current->mm->mm_mt, 0, 0);

	reqprot = prot;

	if (prot == PROT_READ) {
		// printk("[rpcool] change_protection called. prot = PROT_READ.\n");
	} else if (prot == (PROT_READ | PROT_WRITE)) {
		// printk("[rpcool] change_protection called. prot = PROT_WRITE.\n");
	} else {
		printk("[rpcool] change_protection called. prot = invalid prot\n");
		return -EINVAL;
	}

	start = PAGE_ALIGN_DOWN(start);

	if (start & ~PAGE_MASK) {
		printk("[rpcool] start address is not page aligned\n");
		return -EINVAL;
	}

	if (!len)
		return 0;

	len = PAGE_ALIGN(len);
	end = start + len;

	// printk("[rpcool] aligned start: %lx, end: %lx, len: %lx, prot: %lu\n", start, end, len, prot);

	if (!arch_validate_prot(prot, start)) {
		printk("[rpcool] invalid prot (arch validation)\n");
		return -EINVAL;
	}

	if (mmap_write_lock_killable(current->mm)) {
		printk("[rpcool] mmap write lock killable failed\n");
		return -EINTR;
	}

	mas_set(&mas, start);
	vma = mas_find(&mas, ULONG_MAX);
	error = -ENOMEM;
	if (!vma) {
		printk("[rpcool] vma not found\n");
		goto out;
	}

	if (vma->vm_start > start) {
		printk("[rpcool] vma start is greater than start\n");
		goto out;
	}
	if (start > vma->vm_start)
		prev = vma;
	else
		prev = mas_prev(&mas, 0);

	tlb_gather_mmu(&tlb, current->mm);
	for (nstart = start;;) {
		unsigned long mask_off_old_flags;
		unsigned long newflags;

		mask_off_old_flags = VM_READ | VM_WRITE | VM_EXEC |
				     VM_FLAGS_CLEAR;

		newflags = calc_vm_prot_bits(prot, 0);
		newflags |= (vma->vm_flags & ~mask_off_old_flags);

		/*
// newflags >> 4 shift VM_MAY% in place of VM_%
if ((newflags & ~(newflags >> 4)) & VM_ACCESS_FLAGS) {
    printk("[rpcool] new protection flags were not allowed by VM_MAY...
flags\n"); error = -EACCES; break;
}
*/

		/* Allow architectures to sanity-check the new flags */
		if (!arch_validate_flags(newflags)) {
			printk("[rpcool] new protection flags were not allowed by arch\n");
			error = -EINVAL;
			break;
		}

		// TODO do we need this? what does it do?
		error = security_file_mprotect(vma, reqprot, prot);
		if (error) {
			printk("[rpcool] security_file_mprotect failed\n");
			break;
		}

		tmp = vma->vm_end;
		if (tmp > end)
			tmp = end;

		// log_vma_info("prev", prev);
		// log_vma_info("vma", vma);
		// printk("[debug-rpcool] nstart: %lx, end: %lx, tmp: %lx\n", nstart, end, tmp);

		if (vma->vm_ops && vma->vm_ops->mprotect) {
			error = vma->vm_ops->mprotect(vma, nstart, tmp,
						      newflags);
			if (error) {
				printk("[rpcool] vma->vm_ops->mprotect failed\n");
				break;
			}
		}

		error = rpcool_mprotect_fixup(&tlb, vma, &prev, nstart, tmp, newflags);
		if (error) {
			printk("[rpcool] mprotect_fixup failed\n");
			break;
		}

		nstart = tmp;

		if (nstart < prev->vm_end)
			nstart = prev->vm_end;

		// log_vma_info("fixup-prev", prev);
		// log_vma_info("fixup-vma", vma);
		// printk("[debug-rpcool]/2 nstart: %lx, end: %lx, tmp: %lx\n", nstart, end, tmp);
		if (nstart >= end) {
			// printk("[rpcool] nstart is greater than or equal to end: probably end of "
			//        "vma iterations\n");
			break;
		}

		vma = find_vma(current->mm, prev->vm_end);
		if (!vma || vma->vm_start != nstart) {
			printk("[rpcool] vma not found or vma start is not equal to nstart\n");
			error = -ENOMEM;
			break;
		}
		prot = reqprot;
	}
	tlb_finish_mmu(&tlb);

	if (!error && tmp < end && nstart < end) {
		printk("[rpcool] tmp is less than end Error: %d, tmp: %lx, end: %lx, nstart: %lx\n",
		       error, tmp, end, nstart);
		error = -ENOMEM;
	}

out:
	// printk(KERN_INFO "[rpcool] change mem protection finished. return code: %d\n", error);
	mmap_write_unlock(current->mm);
	return error;
}
