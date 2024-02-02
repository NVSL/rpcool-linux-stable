#include "rpcool.h"
#include "seal_queue.h"

#include <linux/fs.h>

static size_t g_alloc_size;
static unsigned long g_user_addr;

static unsigned long vm_flags = VM_READ | VM_WRITE | VM_MAYREAD | VM_SHARED | VM_MAYSHARE;
static unsigned long map_flags = MAP_SHARED | MAP_FIXED;
static unsigned long prot = PROT_READ | PROT_WRITE;

DECLARE_HASHTABLE(g_shared_heaps, SHARED_HEAP_TABLE_BITS);
DECLARE_HASHTABLE(g_connections, CONNECTION_TABLE_BITS);

// ###############################
// ###### Helper Functions #######
// ###############################

int rpcool_map_file(struct task_struct *target_process, struct file *file, size_t mapping_size,
		    unsigned long vma_addr)
{
	unsigned long addr;
	unsigned long populate = 0;
	if (file == NULL) {
		printk("[rpcool] file is NULL\n");
		return -1;
	}

	printk("[rpcool] mapping file %s to process %d at address %lx with size %zu\n",
	       file->f_path.dentry->d_name.name, target_process->pid, vma_addr, mapping_size);

	down_write(&target_process->mm->mmap_lock);
	addr = rpcool_do_mmap(target_process, file, vma_addr, mapping_size, prot, map_flags, 0,
			      &populate, NULL);
	up_write(&target_process->mm->mmap_lock);

	if (IS_ERR_VALUE(addr)) {
		printk("could not mmap, error code: %ld\n", PTR_ERR((void *)addr));
		return -1;
	}
	return 0;
}

struct file *rpcool_create_file(const char *path, size_t size)
{
	struct file *file = shmem_kernel_file_setup(path, size, vm_flags);
	if (IS_ERR(file)) {
		printk("[rpcool] could not create file with path %s\n", path);
	}
	return file;
}

struct shared_heap_entry * _find_shared_heap_entry(const char *path)
{
	struct shared_heap_entry *entry;
	unsigned int hash = full_name_hash(NULL, path, strlen(path));

	printk("[rpcool] find_shared_heap_entry called with path %s\n", path);
	hash_for_each_possible(g_shared_heaps, entry, hnode, hash) {
		if (strcmp(entry->path, path) == 0) {
			return entry;
		}
	}
	return NULL; // Not found
}

struct shared_heap_entry * find_shared_heap_entry(const char __user *path)
{
	const char *shared_heap_path;
	struct shared_heap_entry *shared_heap_entry;

	shared_heap_path = concat_paths_user(path, "shared_heap");
	printk("[rpcool] find_shared_heap_entry called with path %s\n", shared_heap_path);
	shared_heap_entry = _find_shared_heap_entry(shared_heap_path);

	if (shared_heap_entry == NULL) {
		printk("[rpcool] could not find shared heap with path %s\n", shared_heap_path);
	}

	kfree(shared_heap_path);
	return shared_heap_entry;
}

struct connection_entry * _find_connection_entry(const char *path)
{
	struct connection_entry *entry;
	unsigned int hash = full_name_hash(NULL, path, strlen(path));

	hash_for_each_possible(g_connections, entry, hnode, hash) {
		if (strcmp(entry->path, path) == 0) {
			return entry;
		}
	}
	return NULL; // Not found
}

struct connection_entry * find_connection_entry(const char __user *path, long connection_id)
{
	const char *metadata_path; 
	struct connection_entry * entry;
	
	metadata_path = concat_connection_paths_user(path, connection_id, "metadata");
	entry = _find_connection_entry(metadata_path);
	
	if (entry == NULL) {
		printk("[rpcool] could not find connection entry with path %s\n", metadata_path);
	}
	
	kfree(metadata_path);
	return entry;
}

int rpcool_change_protection(unsigned long start, size_t len, unsigned long prot)
{
	unsigned long nstart, end, tmp, reqprot;
	int error;
	struct vm_area_struct *vma, *prev;
	struct mmu_gather tlb;
	MA_STATE(mas, &current->mm->mm_mt, 0, 0);

	reqprot = prot;

	if (prot == PROT_READ) {
		printk("[rpcool] change_protection called. prot = PROT_READ.\n");
	} else if (prot == (PROT_READ | PROT_WRITE)) {
		printk("[rpcool] change_protection called. prot = PROT_WRITE.\n");
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

	printk("[rpcool] aligned start: %lx, end: %lx, len: %lx\n", start, end, len);

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

		mask_off_old_flags = VM_READ | VM_WRITE | VM_EXEC | VM_FLAGS_CLEAR;

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

		if (vma->vm_ops && vma->vm_ops->mprotect) {
			error = vma->vm_ops->mprotect(vma, nstart, tmp, newflags);
			if (error) {
				printk("[rpcool] vma->vm_ops->mprotect failed\n");
				break;
			}
		}

		error = mprotect_fixup(&tlb, vma, &prev, nstart, tmp, newflags);
		if (error) {
			printk("[rpcool] mprotect_fixup failed\n");
			break;
		}

		nstart = tmp;

		if (nstart < prev->vm_end)
			nstart = prev->vm_end;
		if (nstart >= end) {
			printk("[rpcool] nstart is greater than or equal to end: probably end of "
			       "vma iterations\n");
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

	if (!error && tmp < end) {
		printk("[rpcool] tmp is less than end\n");
		error = -ENOMEM;
	}

out:
	printk(KERN_INFO "[rpcool] change mem protection finished. return code: %d\n", error);
	mmap_write_unlock(current->mm);
	return error;
}

// ###############################
// ###### System Calls ###########
// ###############################

// Path examples:
// dev_prefix: /mnt/cxl
// path: kvstore
// shared_heap_path: kvstore/shared_heap
// full_shared_heap_path: /mnt/cxl/kvstore/shared_heap
SYSCALL_DEFINE3(rpcool_create_channel, const char __user *, dev_prefix, const char __user *, path,
		size_t, shared_heap_size)
{
	const char *shared_heap_path;
	const char *full_shared_heap_path;
	const char *dev_prefix_path;
	unsigned int hash_value;
	struct shared_heap_entry *new_entry;
	
	printk("[rpcool] rpcool_create_channel called.\n");
	
	new_entry = kmalloc(sizeof(*new_entry), GFP_KERNEL);
	if (!new_entry)
		return -1;

	dev_prefix_path = get_path_user(dev_prefix);
	shared_heap_path = concat_paths_user(path, "shared_heap");
	full_shared_heap_path = concat_paths(dev_prefix_path, shared_heap_path);
	//        dev_prefix_path, shared_heap_path, shared_heap_size);

	printk("[rpcool] rpcool_create_channel called with dev_prefix: %s, shared_heap_path: %s, full_shared_heap_path: %s, shared_heap_size: %zu\n",
	       dev_prefix_path, shared_heap_path, full_shared_heap_path, shared_heap_size);

	new_entry->dev_prefix_path = dev_prefix_path; // move ownership
	new_entry->path = shared_heap_path; // move ownership
	new_entry->shared_heap = rpcool_create_file(full_shared_heap_path, shared_heap_size);

	kfree(full_shared_heap_path);

	if (IS_ERR(new_entry->shared_heap)) {
		printk("[rpcool] could not create shared heap\n");
		kfree(dev_prefix_path);
		kfree(shared_heap_path);
		kfree(new_entry);
		return PTR_ERR(new_entry->shared_heap);
	}

	hash_value = full_name_hash(NULL, shared_heap_path, strlen(shared_heap_path));
	hash_add(g_shared_heaps, &new_entry->hnode, hash_value);
	printk("[rpcool] channel %s created successfully\n", shared_heap_path);
	
	return init_hash_algorithm();
}

SYSCALL_DEFINE4(rpcool_setup_connection, const char __user *, path, long, connection_id, size_t,
		metadata_size, size_t, private_heap_size)
{
	const char *private_heap_path;
	const char *metadata_path;
	struct file *f_metadata;
	struct file *f_private_heap;
	
	unsigned int hash_value;
	struct shared_heap_entry *shared_heap_entry;
	struct connection_entry *new_entry;
	
	printk("[rpcool] rpcool_setup_connection called.\n");
	new_entry = kmalloc(sizeof(*new_entry), GFP_KERNEL);
	if (!new_entry)
		return -1;

	shared_heap_entry = find_shared_heap_entry(path);
	printk("[rpcool] rpcool_setup_connection before null check.\n");
	if (shared_heap_entry == NULL) {
		kfree(new_entry);
		return -1;
	}
	printk("[rpcool] rpcool_setup_connection entry was not null.\n");

	metadata_path = concat_dev_connection_paths_user(shared_heap_entry->dev_prefix_path, path, connection_id, "metadata");
	printk("[rpcool] rpcool_setup_connection called with metadata_path: %s, connection_id: %ld, metadata_size: %zu, "
	       "private_heap_size: %zu\n",
	       metadata_path, connection_id, metadata_size, private_heap_size);

	f_metadata = rpcool_create_file(metadata_path, metadata_size);
	kfree(metadata_path);

	if (IS_ERR(f_metadata)) {
		printk("[rpcool] could not create metadata\n");
		kfree(new_entry);
		return PTR_ERR(f_metadata);
	}

	private_heap_path = concat_dev_connection_paths_user(shared_heap_entry->dev_prefix_path, path, connection_id, "heap");
	f_private_heap = rpcool_create_file(private_heap_path, private_heap_size);
	kfree(private_heap_path);

	if (IS_ERR(f_private_heap)) {
		fput(f_metadata);
		kfree(new_entry);
		printk("[rpcool] could not create private heap\n");
		return PTR_ERR(f_private_heap);
	}

	new_entry->path = concat_connection_paths_user(path, connection_id, "metadata");
	new_entry->metadata = f_metadata;
	new_entry->private_heap = f_private_heap;
	new_entry->seal_store = initialize_seal_store(f_metadata);
	
	if (IS_ERR(new_entry->seal_store)) {
		printk("[rpcool] could not initialize seal store\n");
		fput(f_metadata);
		fput(f_private_heap);
		kfree(new_entry->path);
		kfree(new_entry);
		return PTR_ERR(new_entry->seal_store);
	}

	hash_value = full_name_hash(NULL, new_entry->path, strlen(new_entry->path));
	hash_add(g_connections, &new_entry->hnode, hash_value);

	return 0;
}

SYSCALL_DEFINE6(rpcool_attach_connection, const char __user *, path, long, connection_id, int,
		target_pid, unsigned long, connection_metadata_vma, unsigned long, private_heap_vma,
		unsigned long, shared_heap_vma)
{
	struct task_struct *target_process;
	const char *kernel_path;
	struct shared_heap_entry *shared_heap_entry;
	struct connection_entry *connection_entry;

	kernel_path = get_path_user(path);
	printk("[rpcool] rpcool_attach_connection called with path: %s, connection_id: %ld, target_pid: %d, "
	       "connection_metadata_vma: %lx, private_heap_vma: %lx, shared_heap_vma: %lx\n",
	       kernel_path, connection_id, target_pid, connection_metadata_vma,
	       private_heap_vma, shared_heap_vma);
	kfree(kernel_path);

	target_process = find_task_by_vpid(target_pid);
	if (target_process == NULL) {
		printk("[rpcool] could not find the task_struct for the pid\n");
		return -1;
	} else {
		printk("[rpcool] found process for pid %d", target_pid);
	}

	shared_heap_entry = find_shared_heap_entry(path);
	if (shared_heap_entry == NULL) {
		return -1;
	}

	connection_entry = find_connection_entry(path, connection_id);

	if (connection_entry == NULL) {
		return -1;
	}

	if (rpcool_map_file(target_process, shared_heap_entry->shared_heap,
			    read_file_size(shared_heap_entry->shared_heap), shared_heap_vma) != 0) {
		return -1;
	}

	if (rpcool_map_file(target_process, connection_entry->private_heap,
			    read_file_size(connection_entry->private_heap),
			    private_heap_vma) != 0) {
		return -1;
	}

	if (rpcool_map_file(target_process, connection_entry->metadata,
			    read_file_size(connection_entry->metadata),
			    connection_metadata_vma) != 0) {
		return -1;
	}

	printk(KERN_INFO "[rpcool] connection_metadata_vma successful!\n");

	return 0;
}

SYSCALL_DEFINE0(rpcool_describe_channel)
{
	struct task_struct *task;
	struct vm_area_struct *vma;
	nodemask_t nodes;

	task = current;

	printk("[rpcool] rpcool_describe_channel called.\n");

	// Find the VMA associated with the user address
	down_read(&task->mm->mmap_lock);
	vma = find_vma(task->mm, g_user_addr);
	if (!vma) {
		printk(KERN_ERR "[rpcool] Failed to find VMA\n");
		up_read(&task->mm->mmap_lock);
		return -ENOMEM;
	}

	print_all_user_addr(vma, g_alloc_size, g_user_addr);
	up_read(&task->mm->mmap_lock);

	return 0;
}

SYSCALL_DEFINE4(rpcool_seal, const char __user *, path, long, connection_id, unsigned long, start,
		size_t, len)
{
	const char *shared_heap_path;
	struct connection_entry *connection_entry;
	int error, result;

	printk("[rpcool] rpcool_seal called.");

	shared_heap_path = concat_paths_user(path, ""); // need to convert path to kernelspace value
	printk("[rpcool] rpcool_seal called with path=%s and connection_id=%ld, start=%lx and len=%zu\n",
	       shared_heap_path, connection_id, start, len);
	kfree(shared_heap_path);

	connection_entry = find_connection_entry(path, connection_id);
	if (connection_entry == NULL) {
		return -1;
	}

	error = rpcool_change_protection(start, len, PROT_READ);
	if (error != 0) {
		pr_err("[rpcool] seal: could not change protection for addr=%lu, len=%lu", start,
		       len);
		return error;
	}

	result = store_seal(connection_entry->seal_store, start, len);
	if (result < 0) {
		printk("[rpcool] seal: could not store seal. reverting protection bits for addr=%lu, len=%lu",
		       start, len);
		error = rpcool_change_protection(start, len, PROT_READ | PROT_WRITE);
		if (error != 0) {
			pr_err("[rpcool] seal: could not change protection back for addr=%lu, len=%lu",
			       start, len);
		}
		return result;
	}

	return result;
}


SYSCALL_DEFINE4(rpcool_release, const char __user *, path, long, connection_id, int, index, const unsigned char __user *, signature)
{
	const char *shared_heap_path;
	struct connection_entry *connection_entry;
	struct SealEntry * seal_entry;
	int error, result;
	size_t start, len;
	uint64_t nonce;


	printk("[rpcool] rpcool_release called with index=%d\n", index);

	shared_heap_path = concat_paths_user(path, ""); // need to convert path to kernelspace value
	printk("[rpcool] rpcool_release called with path=%s and connection_id=%ld, index=%d\n",
	       shared_heap_path, connection_id, index);
	kfree(shared_heap_path);


	connection_entry = find_connection_entry(path, connection_id);
	if (connection_entry == NULL) {
		return -1;
	}

	seal_entry = get_seal(connection_entry->seal_store, index);
	//check for errors IS_ERR(seal_entry)
	if (IS_ERR(seal_entry)) {
		printk("[rpcool] release: could not read (get) seal entry\n");
		return -1;
	}

	start = seal_entry->addr;
	len = seal_entry->len;
	nonce = seal_entry->nonce;
	kfree(seal_entry);
	

	result = validate_signature(signature, HMAC_KEY, strlen(HMAC_KEY), index, nonce);
    if (result != 0) {
        return result;
    }

	error = rpcool_change_protection(start, len, PROT_READ | PROT_WRITE);
	if (error != 0) {
		pr_err("[rpcool] release: could not change protection for addr=%lu, len=%lu", start,
		       len);
		return error;
	}

	printk("[rpcool] release: remmapped the memory region at index=%d\n", index);

	result = release_seal(connection_entry->seal_store, index);
	if (result < 0) {
		printk("[rpcool] release: could not update the seal_store. But remapped the memory region at index=%d\n", index);
		return result;
	}

	return result;
}

SYSCALL_DEFINE3(rpcool_detach_address, int, target_pid, long, vma_addr, size_t, mapping_size)
{
	struct task_struct *target_process;

	printk("[rpcool] rpcool_detach_address called with target_pid=%d, vma_addr=%lx, mapping_size=%zu\n",
	       target_pid, vma_addr, mapping_size);

	target_process = find_task_by_vpid(target_pid);
	if (target_process == NULL) {
		printk("[rpcool] could not find the task_struct for the pid\n");
		return -1;
	} else {
		printk("[rpcool] found process for pid %d", target_pid);
	}

	down_write(&target_process->mm->mmap_lock);
	if (do_munmap(target_process->mm, vma_addr, mapping_size, NULL) != 0) {
		printk("[rpcool] could not munmap\n");
	}
	up_write(&target_process->mm->mmap_lock);
	return 0;
}

SYSCALL_DEFINE2(rpcool_delete_connection, const char __user *, path, long, connection_id)
{
	const char *kernel_path;
	struct connection_entry *entry;

	kernel_path = get_path_user(path);

	printk("[rpcool] rpcool_delete_connection called with path=%s and connection_id=%ld\n",
	       kernel_path, connection_id);

	entry = find_connection_entry(path, connection_id);
	if (entry == NULL) {
		return -1;
	}

	fput(entry->metadata);
	fput(entry->private_heap);

	hash_del(&entry->hnode);
	kfree(entry->seal_store); //this is enough since the kfifo is allocated in the seal store and not as a pointer
	kfree(entry->path);
	kfree(entry);
	return 0;
}

SYSCALL_DEFINE1(rpcool_delete_channel, const char __user *, path)
{
	const char *kernel_path;
	struct shared_heap_entry *entry;

	kernel_path = get_path_user(path);
	printk("[rpcool] rpcool_delete_channel called with path=%s\n", kernel_path);
	kfree(kernel_path);

	entry = find_shared_heap_entry(path);
	if (entry == NULL) {
		return -1;
	}

	fput(entry->shared_heap);

	hash_del(&entry->hnode);
	kfree(entry->dev_prefix_path);
	kfree(entry->path);
	kfree(entry);
	return 0;
}
