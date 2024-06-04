#include "rpcool.h"
#include "seal_queue.h"
#include "stats.h"
#include "mprotect.h"

#include <linux/atomic.h>
#include <linux/idr.h>
#include <linux/fs.h>
#include <linux/ktime.h>
#include <linux/sched.h>
#include <linux/pid_namespace.h>

static unsigned long vm_flags = VM_READ | VM_WRITE | VM_MAYREAD | VM_SHARED |
				VM_MAYSHARE;
static unsigned long map_flags = MAP_SHARED | MAP_FIXED;
static unsigned long prot = PROT_READ | PROT_WRITE;

DECLARE_HASHTABLE(g_shared_heaps, SHARED_HEAP_TABLE_BITS);
DECLARE_HASHTABLE(g_connections, CONNECTION_TABLE_BITS);

static struct connection_entry *g_connections_fd[CONNECTION_DESCRIPTOR_LEN];
static DEFINE_IDA(g_connections_fd_id_allocator);

static int DEBUG_RPCOOL = 0;

// ###############################
// ###### Helper Functions #######
// ###############################

int rpcool_map_file(struct task_struct *target_process, struct file *file,
		    size_t mapping_size, unsigned long vma_addr)
{
	unsigned long addr;
	unsigned long populate = 0;
	if (file == NULL) {
		printk("[rpcool] file is NULL\n");
		return -1;
	}

	printk("[rpcool] mapping file %s to process %d at address %lx with size %zu\n",
	       file->f_path.dentry->d_name.name, target_process->pid, vma_addr,
	       mapping_size);

	down_write(&target_process->mm->mmap_lock);
	addr = rpcool_do_mmap(target_process, file, vma_addr, mapping_size,
			      prot, map_flags, 0, &populate, NULL);
	up_write(&target_process->mm->mmap_lock);

	if (IS_ERR_VALUE(addr)) {
		printk("could not mmap, error code: %ld\n",
		       PTR_ERR((void *)addr));
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

struct shared_heap_entry *_find_shared_heap_entry(const char *path)
{
	struct shared_heap_entry *entry;
	unsigned int hash = full_name_hash(NULL, path, strlen(path));

	// printk("[rpcool] find_shared_heap_entry called with path %s\n", path);
	hash_for_each_possible(g_shared_heaps, entry, hnode, hash) {
		if (strcmp(entry->path, path) == 0) {
			return entry;
		}
	}
	return NULL; // Not found
}

struct shared_heap_entry *find_shared_heap_entry(const char __user *path)
{
	const char *shared_heap_path;
	struct shared_heap_entry *shared_heap_entry;

	shared_heap_path = concat_paths_user(path, "shared_heap");
	// printk("[rpcool] find_shared_heap_entry called with path %s\n", shared_heap_path);
	shared_heap_entry = _find_shared_heap_entry(shared_heap_path);

	if (shared_heap_entry == NULL) {
		printk("[rpcool] could not find shared heap with path %s\n",
		       shared_heap_path);
	}

	kfree(shared_heap_path);
	return shared_heap_entry;
}

struct connection_entry *_find_connection_entry(const char *path)
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

struct connection_entry *find_connection_entry(const char __user *path,
					       long connection_id)
{
	const char *metadata_path;
	struct connection_entry *entry;

	metadata_path =
		concat_connection_paths_user(path, connection_id, "metadata");
	entry = _find_connection_entry(metadata_path);

	if (entry == NULL) {
		printk("[rpcool] could not find connection entry with path %s\n",
		       metadata_path);
	}

	kfree(metadata_path);
	return entry;
}

// ###############################
// ###### System Calls ###########
// ###############################

void free_connection_entry(struct connection_entry *entry)
{
	printk("[rpcool] clearing connection entry with path %s, shared_path: %s, id: %ld, fd: %d\n", entry->path, entry->shared_heap_entry->path, entry->connection_id, entry->connection_fd);
    if (entry->connection_fd != -1) {
        g_connections_fd[entry->connection_fd] = NULL;
        // ida_free(g_connections_fd_id_allocator, entry->connection_fd);
        entry->connection_fd = -1;
    }

    fput(entry->metadata);
    fput(entry->private_heap);

    free_seal_store(entry->seal_store);
    kfree(entry->path);
    hash_del(&entry->hnode);
    kfree(entry);
}


void free_all_connections(void)
{
    struct connection_entry *entry;
    struct hlist_node *tmp;
    int bkt;

    hash_for_each_safe(g_connections, bkt, tmp, entry, hnode) {
        free_connection_entry(entry);
    }
}

void free_shared_heap_entry(struct shared_heap_entry *entry)
{
	printk("[rpcool] clearing shared heap entry with path %s : %s\n", entry->dev_prefix_path, entry->path);
    fput(entry->shared_heap);

    kfree(entry->dev_prefix_path);
    kfree(entry->path);
    hash_del(&entry->hnode);
    kfree(entry);
}

void free_all_shared_heap_entries(void)
{
    struct shared_heap_entry *entry;
    struct hlist_node *tmp;
    int bkt;

    hash_for_each_safe(g_shared_heaps, bkt, tmp, entry, hnode) {
        free_shared_heap_entry(entry);
    }
}


SYSCALL_DEFINE0(rpcool_clean_up) {

	free_all_connections();
	free_all_shared_heap_entries();
	return 0;
}

// Path examples:
// dev_prefix: /mnt/cxl
// path: kvstore
// shared_heap_path: kvstore/shared_heap
// full_shared_heap_path: /mnt/cxl/kvstore/shared_heap
SYSCALL_DEFINE3(rpcool_create_channel, const char __user *, dev_prefix,
		const char __user *, path, size_t, shared_heap_size)
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
	       dev_prefix_path, shared_heap_path, full_shared_heap_path,
	       shared_heap_size);

	new_entry->dev_prefix_path = dev_prefix_path; // move ownership
	new_entry->path = shared_heap_path; // move ownership
	new_entry->shared_heap =
		rpcool_create_file(full_shared_heap_path, shared_heap_size);
	new_entry->size = shared_heap_size;
	new_entry->vma = 0;

	kfree(full_shared_heap_path);

	if (IS_ERR(new_entry->shared_heap)) {
		printk("[rpcool] could not create shared heap\n");
		kfree(dev_prefix_path);
		kfree(shared_heap_path);
		kfree(new_entry);
		return PTR_ERR(new_entry->shared_heap);
	}

	hash_value = full_name_hash(NULL, shared_heap_path,
				    strlen(shared_heap_path));
	hash_add(g_shared_heaps, &new_entry->hnode, hash_value);
	printk("[rpcool] channel %s created successfully\n", shared_heap_path);

	return init_hash_algorithm();
}

SYSCALL_DEFINE4(rpcool_setup_connection, const char __user *, path, long,
		connection_id, size_t, metadata_size, size_t, private_heap_size)
{
	const char *private_heap_path;
	const char *metadata_path;
	struct file *f_metadata;
	struct file *f_private_heap;

	int fd;

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

	metadata_path = concat_dev_connection_paths_user(
		shared_heap_entry->dev_prefix_path, path, connection_id,
		"metadata");
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

	private_heap_path = concat_dev_connection_paths_user(
		shared_heap_entry->dev_prefix_path, path, connection_id,
		"heap");
	f_private_heap =
		rpcool_create_file(private_heap_path, private_heap_size);
	kfree(private_heap_path);

	if (IS_ERR(f_private_heap)) {
		fput(f_metadata);
		kfree(new_entry);
		printk("[rpcool] could not create private heap\n");
		return PTR_ERR(f_private_heap);
	}

	new_entry->path =
		concat_connection_paths_user(path, connection_id, "metadata");
	new_entry->metadata = f_metadata;
	new_entry->private_heap = f_private_heap;
	new_entry->seal_store = initialize_seal_store(f_metadata);
	new_entry->shared_heap_entry = shared_heap_entry;
	new_entry->connection_id = connection_id;

	if (IS_ERR(new_entry->seal_store)) {
		printk("[rpcool] could not initialize seal store\n");
		fput(f_metadata);
		fput(f_private_heap);
		kfree(new_entry->path);
		kfree(new_entry);
		return PTR_ERR(new_entry->seal_store);
	}

	fd = ida_alloc(&g_connections_fd_id_allocator, GFP_KERNEL);
	if (fd < 0 || fd >= CONNECTION_DESCRIPTOR_LEN) {
		printk("[rpcool] could not allocate fd\n");
		if (fd >= CONNECTION_DESCRIPTOR_LEN)
			printk("[rpcool] fd is too large\n");
		fput(f_metadata);
		fput(f_private_heap);
		kfree(new_entry->path);
		kfree(new_entry->seal_store);
		kfree(new_entry);
		return -1;
	}

	new_entry->connection_fd = fd;
	g_connections_fd[fd] = new_entry;

	hash_value =
		full_name_hash(NULL, new_entry->path, strlen(new_entry->path));
	hash_add(g_connections, &new_entry->hnode, hash_value);

	return fd;
}

SYSCALL_DEFINE6(rpcool_attach_connection, const char __user *, path, long,
		connection_id, int, target_pid, unsigned long,
		connection_metadata_vma, unsigned long, private_heap_vma,
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
		printk("[rpcool] rpcool_attach_connection could not find the task_struct for the pid\n");
		return -1;
	} else {
		printk("[rpcool] rpcool_attach_connection found process for pid %d", target_pid);
	}

	connection_entry = find_connection_entry(path, connection_id);

	if (connection_entry == NULL) {
		return -1;
	}

	shared_heap_entry = connection_entry->shared_heap_entry;
	if (shared_heap_entry == NULL) {
		return -1;
	}
	shared_heap_entry->vma = shared_heap_vma;

	if (is_address_mapped(target_process, shared_heap_vma) == 1) {
		printk("[rpcool] rpcool_attach_connection shared heap is already mapped to pid=%d. skipping the remapping ...\n", target_pid);
	} else {
		
		printk("[rpcool] rpcool_attach_connection mapping the shared heap to pid=%d\n", target_pid);
		if (rpcool_map_file(target_process, shared_heap_entry->shared_heap,
			    read_file_size(shared_heap_entry->shared_heap),
			    shared_heap_vma) != 0) {
			return -1;
		}
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
	/*struct task_struct *task;
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

	return 0;*/
	// static syscall_time_stats_t syscall_stats = {
	// 	{ "rpcool_describe_channel" }, 0, 0
	// };
	// ktime_t start_time = start_time_measure();
	// //noop
	// end_time_measure(start_time, &syscall_stats, 40000);
	return 0;
}

SYSCALL_DEFINE3(rpcool_create_scope, int, connection_fd, unsigned long, start,
		size_t, len)
{
	struct connection_entry *connection_entry;
	struct vm_area_struct *new_vma;
	int error, id;

	if (DEBUG_RPCOOL) {
		printk("[rpcool] create_scope called with connection fd=%d, start=%lx, len=%zu\n",
		       connection_fd, start, len);
	}

	if (connection_fd < 0) {
		printk("[rpcool] create_scope: invalid connection_fd\n");
		return -EINVAL;
	}

	connection_entry = g_connections_fd[connection_fd];
	if (!connection_entry) {
		return -ENODEV;
	}

	if (start > 0x700000000000 || start < 0x600000000000) {
		pr_err("[rpcool] create_scope: start address is out of range for rpcool shm. start=%lx\n", start);
		return -EINVAL;
	}

	struct SealStore *seal_store = connection_entry->seal_store;

	// Generate an ID
	id = ida_alloc(&seal_store->scope_id_allocator, GFP_KERNEL);
	if (id < 0) {
		pr_err("[rpcool] create_scope: could not allocate ID\n");
		return id;
	}

	new_vma = rpcool_change_protection(start, len, PROT_READ);
	if (IS_ERR(new_vma)) {
		pr_err("[rpcool] create_scope: could not change protection to read-only for addr=%lx, len=%zu\n",
		       start, len);
		ida_free(&seal_store->scope_id_allocator, id);
		return PTR_ERR(new_vma);
	}

	if (new_vma->vm_start != start || new_vma->vm_end != start + len) {
		pr_err("[rpcool] create_scope (R): the returned vma does not match the requested range. new_vma->vm_start=%lx, new_vma->vm_end=%lx, request_start=%lx, request_len=%zu, request_end=%lx\n",
		       new_vma->vm_start, new_vma->vm_end, start, len,
		       start + len);
		return -1;
	}

	new_vma = rpcool_change_protection(start, len, PROT_READ | PROT_WRITE);
	if (IS_ERR(new_vma)) {
		pr_err("[rpcool] create_scope: could not change protection back to read-write for addr=%lx, len=%zu\n",
		       start, len);
		ida_free(&seal_store->scope_id_allocator, id);
		return PTR_ERR(new_vma);
	}

	if (new_vma->vm_start != start || new_vma->vm_end != start + len) {
		pr_err("[rpcool] create_scope (RW): the returned vma does not match the requested range. new_vma->vm_start=%lx, new_vma->vm_end=%lx, request_start=%lx, request_len=%zu, request_end=%lx\n",
		       new_vma->vm_start, new_vma->vm_end, start, len,
		       start + len);
		return -1;
	}

	seal_store->vma_cache[id] = new_vma;
	atomic_max(&seal_store->vma_cache_size, id + 1); // size is 1-based

	error = store_seal_at_index(connection_entry->seal_store, start, len,
				    id);

	if (error < 0) {
		printk("[rpcool] create_scope: could not store seal metadata (SealEntry), start=%lx, len=%zu\n",
		       start, len);
		return -1;
	}

	if (DEBUG_RPCOOL) {
	printk("[rpcool] create_scope: scope created with fd=%d, id=%d, start=%lx, end=%lx, vma_itself=%lx, vma_cache=%lx\n",
		connection_fd, id, seal_store->vma_cache[id]->vm_start, seal_store->vma_cache[id]->vm_end, seal_store->vma_cache[id], seal_store->vma_cache);
	}
	return id;
}

/* @return 0 on success, -1 on failure
 * @note This will reset seal_counter to 1 (and not 0) because the caller will continue to seal after this release
*/

int batch_release(struct connection_entry *connection_entry,
		  unsigned long release_threshold)
{
	struct shared_heap_entry *shared_heap_entry;
	struct vm_area_struct *change_prot_result;
	ktime_t release_start_time;
	const int report_time_frequency =
		(int)max(1000000UL / release_threshold / 25UL, 1UL);
	static syscall_time_stats_t syscall_batch_release_stats = {
		{ "rpcool_batch_release" }, 0, 0
	};
	release_start_time = start_time_measure();

	if (!mutex_trylock(&connection_entry->seal_store
				    ->seal_only_one_should_call_release_lock)) {
		arch_atomic_dec(&connection_entry->seal_store->seal_counter);
		return -1;
	}

	if (DEBUG_RPCOOL) {
		printk("[rpcool] batch_release called with release_threshold=%lu, vma_size=%d\n",
		       release_threshold,
		       arch_atomic_read(
			       &connection_entry->seal_store->vma_cache_size));
	}

	// unsigned long start_0 = connection_entry->seal_store->vma_cache[0]->vm_start;
	// int vma_array_size =  arch_atomic_read(&connection_entry->seal_store->vma_cache_size);
	// printk("[rpcool] we cool.");
	// unsigned long start_n = connection_entry->seal_store->vma_cache[vma_array_size-1]->vm_start;
	// printk("[rpcool] batch_release called with release_threshold=%lu, vma_size=%d, vma[0].start=%lx, vma[n].start=%lx\n",
	// 	       release_threshold, vma_array_size, start_0, start_n);

	// pr_err("[rpcool] seal: max queue length reached\n");
	// only one thread will call release_all
	uint64_t release_counter =
		read_release_counter(connection_entry->seal_store);
	// int retry_count = 0;
	while (release_counter < release_threshold) {
		// if (retry_count % 5000 == 0)
		// 	pr_info("[rpcool] release counter is %lu. waiting for it to reach %lu, caller_pid=%d\n", release_counter, release_threshold,task_tgid_nr_ns(current, &init_pid_ns));
		// retry_count++;
		schedule();
		release_counter =
			read_release_counter(connection_entry->seal_store);
	}
	// if (retry_count > 10)
	// 	pr_info("[rpcool] wait for the release counter took %d retries\n", retry_count);
	// pr_info("[rpcool] release counter reached release_threshold\n");
	// shared_heap_entry = connection_entry->shared_heap_entry;
	// if (shared_heap_entry == NULL) {
	// 	pr_err("[rpcool] could not find shared heap entry in release!\n");
	// 	mutex_unlock(&connection_entry->seal_store
	// 			      ->seal_only_one_should_call_release_lock);
	// 	return -1;
	// }
	//release the entire heap
	// unsigned long vma = shared_heap_entry->vma;
	// unsigned long size = shared_heap_entry->size;
	// pr_info("[rpcool] release_all called with vma=%lx, vma=%lu, size=%lu\n", vma, vma, size);

	change_prot_result = rpcool_change_protection_vma_all(
		connection_entry->seal_store->vma_cache,
		arch_atomic_read(&connection_entry->seal_store->vma_cache_size),
		PROT_READ | PROT_WRITE);
	if (IS_ERR(change_prot_result)) {
		pr_err("[rpcool] release_all: could not change protection using rpcool_change_protection_vma_all, error: %ld",
		       PTR_ERR(change_prot_result));
		mutex_unlock(&connection_entry->seal_store
				      ->seal_only_one_should_call_release_lock);
		return PTR_ERR(change_prot_result);
	}
	reset_release_counter(connection_entry->seal_store);
	arch_atomic_set(
		&connection_entry->seal_store->seal_counter,
		1); // because the caller will continue to release and use the index 0 itself
	// pr_info("[rpcool] released everything!\n");
	mutex_unlock(&connection_entry->seal_store
			      ->seal_only_one_should_call_release_lock);
	end_time_measure(release_start_time, &syscall_batch_release_stats,
			 report_time_frequency);
	return 0;
}

SYSCALL_DEFINE5(rpcool_seal, int, connection_fd, int, scope_index, int, mode,
		unsigned long, release_threshold, unsigned long, expected_start)
{
	struct connection_entry *connection_entry;
	struct vm_area_struct *change_prot_result, *vma;
	int result;
	int index = -1;
	unsigned long start;
	size_t len;
	ktime_t start_time;
	static syscall_time_stats_t syscall_stats = { { "rpcool_seal" }, 0, 0 };
	// start_time = start_time_measure();

	if (DEBUG_RPCOOL) {
		printk("[rpcool] rpcool_seal called with connection fd=%d, scope_index=%d, mode=%d, release_threshold=%lu\n",
		       connection_fd, scope_index, mode, release_threshold);
	}
	if (connection_fd < 0) {
		printk("[rpcool] seal: invalid connection_fd\n");
		return -1;
	}
	if (scope_index < 0) {
		printk("[rpcool] seal: invalid scope_index\n");
		return -1;
	}

	connection_entry = g_connections_fd[connection_fd];
	if (connection_entry == NULL) {
		return -1;
	}

	if (mode == SEAL_BATCH_RELEASE) {
		index = arch_atomic_fetch_inc(
			&connection_entry->seal_store->seal_counter);
		if (index >= release_threshold) {
			result = batch_release(connection_entry,
					       release_threshold);
			if (result != 0)
				return result;
			// index = 0; // batch_release will reset the counter to 1 and hence 0 will be ours to use
			//start_time = start_time_measure(); // reset the start_timer for seal so that we will not include the release time in the seal time
		} // continue with the seal
	}

	vma = connection_entry->seal_store->vma_cache[scope_index];
	start = vma->vm_start;
	len = vma->vm_end - vma->vm_start;

	if (start != expected_start) {
		pr_err("[rpcool] seal: start address does not match the expected start address. fd=%d, scope_index=%d, start=%lx, expected_start=%lx",
		       connection_fd, scope_index, start, expected_start);
		return -1;
	}
	
	change_prot_result = rpcool_change_protection_vma(vma, PROT_READ);
	if (IS_ERR(change_prot_result)) {
		pr_err("[rpcool] seal: could not change protection for addr=%lx, len=%lu, error=%ld",
		       start, len, PTR_ERR(change_prot_result));
		return PTR_ERR(change_prot_result);
	}

	result = reset_seal_nonce_at_index(connection_entry->seal_store,
					   scope_index);
	if (result < 0) {
		printk("[rpcool] seal: could not store seal. reverting protection bits for addr=%lx, len=%lu",
		       start, len);
		change_prot_result = rpcool_change_protection_vma(
			vma, PROT_READ | PROT_WRITE);
		if (IS_ERR(change_prot_result)) {
			pr_err("[rpcool] seal: could not change protection back for addr=%lu, len=%lu, error=%ld",
			       start, len, PTR_ERR(change_prot_result));
		}
		return result;
	}

	// end_time_measure(start_time, &syscall_stats, 40000);
	return result;
}

SYSCALL_DEFINE3(rpcool_release, int, connection_fd, int, index,
		const unsigned char __user *, signature)
{
	struct connection_entry *connection_entry;
	struct SealEntry *seal_entry;
	struct vm_area_struct *change_prot_result;

	int result;
	size_t start, len;
	uint64_t nonce;
	ktime_t start_time;
	static syscall_time_stats_t syscall_stats = { { "rpcool_release" },
						      0,
						      0 };
	start_time = start_time_measure();

	// printk("[rpcool] rpcool_release called with index=%d\n", index);

	if (DEBUG_RPCOOL) {
		printk("[rpcool] rpcool_release called with connection_fd=%d, index=%d\n",
		       connection_fd, index);
	}

	if (connection_fd < 0) {
		printk("[rpcool] seal: invalid connection_fd\n");
		return -1;
	}
	connection_entry = g_connections_fd[connection_fd];
	if (connection_entry == NULL) {
		return -1;
	}

	seal_entry = get_seal(connection_entry->seal_store, index);
	if (IS_ERR(seal_entry)) {
		printk("[rpcool] release: could not read (get) seal entry\n");
		return -1;
	}

	start = seal_entry->addr;
	len = seal_entry->len;
	nonce = seal_entry->nonce;

	// result = validate_signature(signature, HMAC_KEY, strlen(HMAC_KEY), index, nonce);
	// if (result != 0) {

	if (nonce == 0) { // repurposing nonce to be `is_receiver_done`
		kfree(seal_entry);
		printk("[rpcool] release: could not release index=%d, nonce is 0\n",
		       index);
		return result;
	}

	change_prot_result =
		rpcool_change_protection(start, len, PROT_READ | PROT_WRITE);
	if (IS_ERR(change_prot_result)) {
		pr_err("[rpcool] release: could not change protection for addr=%lx, len=%lu, error: %ld",
		       start, len, PTR_ERR(change_prot_result));
		kfree(seal_entry);
		return PTR_ERR(change_prot_result);
	}

	// printk("[rpcool] release: remmapped the memory region at index=%d\n", index);

	// kfree(seal_entry);
	end_time_measure(start_time, &syscall_stats, 40000);
	return result;
}

SYSCALL_DEFINE3(rpcool_detach_address, int, target_pid, long, vma_addr, size_t,
		mapping_size)
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

SYSCALL_DEFINE2(rpcool_delete_connection, const char __user *, path, long,
		connection_id)
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

	if (entry->connection_fd != -1) {
		g_connections_fd[entry->connection_fd] = NULL;
		ida_free(&g_connections_fd_id_allocator, entry->connection_fd);
		entry->connection_fd = -1;
	}

	fput(entry->metadata);
	fput(entry->private_heap);

	hash_del(&entry->hnode);
	free_seal_store(entry->seal_store);
	kfree(entry->path);
	kfree(entry);
	return 0;
}

SYSCALL_DEFINE1(rpcool_delete_channel, const char __user *, path)
{
	const char *kernel_path;
	struct shared_heap_entry *entry;

	kernel_path = get_path_user(path);
	printk("[rpcool] rpcool_delete_channel called with path=%s\n",
	       kernel_path);
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
