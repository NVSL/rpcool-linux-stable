#include "mprotect.h"
#include <linux/mm.h>

void log_vma_info(const char *str, struct vm_area_struct *vma)
{
	printk("[debug-rpcool] %s - VMA Info - Start: %lx, End: %lx, Page Prot: %lx\n",
	       str, vma->vm_start, vma->vm_end, pgprot_val(vma->vm_page_prot));
}

struct vm_area_struct *rpcool_change_protection(unsigned long start, size_t len,
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
		return ERR_PTR(-EINVAL);
	}

	start = PAGE_ALIGN_DOWN(start);

	if (start & ~PAGE_MASK) {
		printk("[rpcool] start address is not page aligned\n");
		return ERR_PTR(-EINVAL);
	}

	if (!len)
		return ERR_PTR(-EINVAL);

	len = PAGE_ALIGN(len);
	end = start + len;

	// printk("[rpcool] aligned start: %lx, end: %lx, len: %lx, prot: %lu\n", start, end, len, prot);

	if (!arch_validate_prot(prot, start)) {
		printk("[rpcool] invalid prot (arch validation)\n");
		return ERR_PTR(-EINVAL);
	}

	if (mmap_write_lock_killable(current->mm)) {
		printk("[rpcool] mmap write lock killable failed\n");
		return ERR_PTR(-EINTR);
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
		// error = security_file_mprotect(vma, reqprot, prot);
		// if (error) {
		// 	printk("[rpcool] security_file_mprotect failed\n");
		// 	break;
		// }

		tmp = vma->vm_end;
		if (tmp > end)
			tmp = end;

		// log_vma_info("prev", prev);
		// log_vma_info("vma", vma);
		// printk("[debug-rpcool] nstart: %lx, end: %lx, tmp: %lx\n", nstart, end, tmp);

		if (vma->vm_ops && vma->vm_ops->mprotect) {
			printk("[rpcool] rpcool_change_protection: calling vma->vm_ops->mprotect\n");
			error = vma->vm_ops->mprotect(vma, nstart, tmp,
						      newflags);
			if (error) {
				printk("[rpcool] vma->vm_ops->mprotect failed\n");
				break;
			}
		}

		error = rpcool_mprotect_fixup(&tlb, vma, &prev, nstart, tmp,
					      newflags);
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
	// printk("[rpcool] change_protection finished. start: %lx, len: %lx, prot: %lu, error: %d\n", start, len, prot, error);
	if (error != 0) {
		return ERR_PTR(error);
	}
	// log_vma_info("return_vma", vma);
	return vma;
}

struct vm_area_struct *rpcool_change_protection_vma(struct vm_area_struct *vma,
						    unsigned long prot)
{
	unsigned long reqprot;
	int error = 0;
	struct vm_area_struct *prev;
	struct mmu_gather tlb;

	reqprot = prot;

	if (prot == PROT_READ) {
		// printk("[rpcool] change_protection called. prot = PROT_READ.\n");
	} else if (prot == (PROT_READ | PROT_WRITE)) {
		// printk("[rpcool] change_protection called. prot = PROT_WRITE.\n");
	} else {
		printk("[rpcool] change_protection called. prot = invalid prot\n");
		return ERR_PTR(-EINVAL);
	}

	if (!vma) {
		printk("[rpcool] rpcool_change_protection_vma: vma not found\n");
		return ERR_PTR(-EINVAL);
	}

	if (mmap_write_lock_killable(current->mm)) {
		printk("[rpcool] mmap write lock killable failed\n");
		return ERR_PTR(-EINTR);
	}

	prev = vma;

	tlb_gather_mmu(&tlb, current->mm);
	{
		unsigned long mask_off_old_flags;
		unsigned long newflags;

		mask_off_old_flags = VM_READ | VM_WRITE | VM_EXEC |
				     VM_FLAGS_CLEAR;

		newflags = calc_vm_prot_bits(prot, 0);
		newflags |= (vma->vm_flags & ~mask_off_old_flags);

		/* Allow architectures to sanity-check the new flags */
		if (!arch_validate_flags(newflags)) {
			printk("[rpcool] new protection flags were not allowed by arch\n");
			error = -EINVAL;
			goto out;
		}

		if (vma->vm_ops && vma->vm_ops->mprotect) {
			printk("[rpcool] rpcool_change_protection_vma: calling vma->vm_ops->mprotect\n");
			error = vma->vm_ops->mprotect(vma, vma->vm_start,
						      vma->vm_end, newflags);
			if (error) {
				printk("[rpcool] vma->vm_ops->mprotect failed\n");
				goto out;
			}
		}

		error = rpcool_mprotect_fixup(&tlb, vma, &prev, vma->vm_start,
					      vma->vm_end, newflags);
		if (error) {
			printk("[rpcool] mprotect_fixup failed\n");
			goto out;
		}
	}
	tlb_finish_mmu(&tlb);

out:
	// printk(KERN_INFO "[rpcool] change mem protection finished. return code: %d\n", error);
	mmap_write_unlock(current->mm);
	if (error != 0) {
		return ERR_PTR(error);
	}
	return vma;
}

struct vm_area_struct *
rpcool_change_protection_vma_all(struct vm_area_struct **vma_array,
				 size_t vma_array_size, unsigned long prot)
{
	unsigned long reqprot;
	int error = 0;
	struct vm_area_struct *prev, *vma;
	struct mmu_gather tlb;

	reqprot = prot;

	if (prot == PROT_READ) {
		// printk("[rpcool] change_protection called. prot = PROT_READ.\n");
	} else if (prot == (PROT_READ | PROT_WRITE)) {
		// printk("[rpcool] change_protection called. prot = PROT_WRITE.\n");
	} else {
		printk("[rpcool] change_protection called. prot = invalid prot\n");
		return ERR_PTR(-EINVAL);
	}

	if (!vma_array) {
		printk("[rpcool] vma array is null\n");
		return ERR_PTR(-EINVAL);
	}

	if (mmap_write_lock_killable(current->mm)) {
		printk("[rpcool] mmap write lock killable failed\n");
		return ERR_PTR(-EINTR);
	}

	tlb_gather_mmu(&tlb, current->mm);
	{
		for (size_t i = 0; i < vma_array_size; i++) {
			unsigned long mask_off_old_flags;
			unsigned long newflags;

			mask_off_old_flags = VM_READ | VM_WRITE | VM_EXEC |
					     VM_FLAGS_CLEAR;

			vma = vma_array[i];
			prev = vma;
			if (vma == NULL)
				continue;

			newflags = calc_vm_prot_bits(prot, 0);
			newflags |= (vma->vm_flags & ~mask_off_old_flags);

			/* Allow architectures to sanity-check the new flags */
			if (!arch_validate_flags(newflags)) {
				printk("[rpcool] new protection flags were not allowed by arch on vma with scope_id=%zu, start=%lx, end=%lx\n",
				       i, vma->vm_start, vma->vm_end);
				error = -EINVAL;
				goto out;
			}

			if (vma->vm_ops && vma->vm_ops->mprotect) {
				error = vma->vm_ops->mprotect(vma,
							      vma->vm_start,
							      vma->vm_end,
							      newflags);
				if (error) {
					printk("[rpcool] vma->vm_ops->mprotect failedon vma with scope_id=%zu, start=%lx, end=%lx\n",
					       i, vma->vm_start, vma->vm_end);
					goto out;
				}
			}

			error = rpcool_mprotect_fixup(&tlb, vma, &prev,
						      vma->vm_start,
						      vma->vm_end, newflags);
			if (error) {
				printk("[rpcool] mprotect_fixup failed on vma with scope_id=%zu, start=%lx, end=%lx\n",
				       i, vma->vm_start, vma->vm_end);
				goto out;
			}
		}
	}
	tlb_finish_mmu(&tlb);

out:
	// printk(KERN_INFO "[rpcool] change mem protection finished. return code: %d\n", error);
	mmap_write_unlock(current->mm);
	if (error != 0) {
		return ERR_PTR(error);
	}
	return vma;
}