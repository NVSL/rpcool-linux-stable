#include "seal_queue.h"

#include <linux/err.h>

#define KEY_POS 0
#define RELEASE_COUNTER_POS 48
#define ENTRIES_START_POS RELEASE_COUNTER_POS + 8

#define HMAC_KEY2 "8NQEL3eZmLj7IgYwkeKnzLtE+qzwEJu9"

uint64_t get_current_nonce(struct SealStore *seal_store, ssize_t index)
{
	loff_t pos;
	ssize_t result;
	uint64_t nonce;

	// Calculate the position of the nonce in the file
	pos = ENTRIES_START_POS + index * sizeof(struct SealEntry) +
	      SEAL_ENTRY_NONCE_POSITION;

	// Read only the nonce part
	result = kernel_read(seal_store->f_metadata, &nonce, sizeof(nonce),
			     &pos);
	if (result < 0) {
		pr_err("[rpcool] Error reading nonce from queue: %zd\n",
		       result);
		return UINT_MAX; // this is bad and buggy!
	}

	return nonce;
}

int store_seal_at_index(struct SealStore *seal_store, size_t addr, size_t len,
			int index)
{
	loff_t pos;
	ssize_t result;
	struct SealEntry entry = { .addr = addr, .len = len, .nonce = 0 };

	pos = ENTRIES_START_POS + index * sizeof(struct SealEntry);
	result = kernel_write(seal_store->f_metadata, &entry,
			      sizeof(struct SealEntry),
			      &pos); // also stores the new nonce
	if (result < 0) {
		pr_err("[rpcool] Error writing entry to queue: %zd\n", result);
		return result;
	}

	return index;
}

int reset_seal_nonce_at_index(struct SealStore *seal_store, int index)
{
	loff_t pos;
	ssize_t result;
	struct SealEntry entry = { .addr = 0, .len = 0, .nonce = 0 };

	pos = ENTRIES_START_POS + index * sizeof(struct SealEntry) +
	      sizeof(entry.addr) + sizeof(entry.len);
	result = kernel_write(seal_store->f_metadata, &entry.nonce,
			      sizeof(entry.nonce),
			      &pos); // also stores the new nonce
	if (result < 0) {
		pr_err("[rpcool] Error writing entry to queue: %zd\n", result);
		return result;
	}

	return index;
}

struct SealStore *initialize_seal_store(struct file *f_metadata)
{
	struct SealStore *seal_store;
	loff_t pos;
	ssize_t result;
	int i;

	pr_info("[rpcool] initializing seal store\n");

	seal_store = kmalloc(sizeof(struct SealStore), GFP_KERNEL);
	if (!seal_store) {
		pr_err("[rpcool] Error allocating memory for seal store\n");
		return ERR_PTR(-ENOMEM);
	}

	seal_store->f_metadata = f_metadata;
	atomic_set(&seal_store->seal_counter, 0);
	mutex_init(&seal_store->seal_only_one_should_call_release_lock);

	if (reset_release_counter(seal_store) != 0) {
		kfree(seal_store);
		pr_err("[rpcool] Error resetting release counter to zero\n");
		return ERR_PTR(-1);
	}

	seal_store->vma_cache = vzalloc(MAX_SCOPE_COUNT * sizeof(struct vm_area_struct *));
	if (!seal_store->vma_cache) {
		kfree(seal_store);
		pr_err("[rpcool] Error allocating memory for vma cache\n");
		return ERR_PTR(-ENOMEM);
	}
	arch_atomic_set(&seal_store->vma_cache_size, 0);
	ida_init(&(seal_store->scope_id_allocator));

	return seal_store;
}

struct SealEntry *get_seal(struct SealStore *seal_store, ssize_t index)
{
	loff_t pos;
	ssize_t result;

	struct SealEntry *entry = kmalloc(sizeof(struct SealEntry), GFP_KERNEL);
	if (!entry) {
		pr_err("[rpcool] Error allocating memory for seal entry\n");
		return ERR_PTR(-ENOMEM);
	}
	pos = ENTRIES_START_POS + index * sizeof(struct SealEntry);
	result = kernel_read(seal_store->f_metadata, entry,
			     sizeof(struct SealEntry), &pos);
	if (result < 0) {
		pr_err("[rpcool] Error reading entry from queue: %zd\n",
		       result);
		return ERR_PTR(result);
	}
	return entry;
}

uint64_t read_release_counter(struct SealStore *seal_store)
{
	loff_t pos = RELEASE_COUNTER_POS;
	uint64_t release_counter = 0;
	ssize_t result = kernel_read(seal_store->f_metadata, &release_counter,
				     sizeof(uint64_t), &pos);
	if (result < 0) {
		pr_err("[rpcool] Error reading release counter: %zd\n", result);
		return 0;
	}
	return release_counter;
}

int reset_release_counter(struct SealStore *seal_store)
{
	loff_t pos = RELEASE_COUNTER_POS;
	uint64_t release_counter = 0;
	ssize_t result = kernel_write(seal_store->f_metadata, &release_counter,
				      sizeof(uint64_t), &pos);
	if (result < 0) {
		pr_err("[rpcool] Error resetting release counter to zero: %zd\n",
		       result);
		return -1;
	}
	return 0;
}

int atomic_max(atomic_t *v, int max)
{
	int old, curr;
	curr = old = atomic_read(v);
	while (old < max && (curr = atomic_cmpxchg(v, old, max)) != old) {
		old = curr;
	}
	return curr;
}

void free_seal_store(struct SealStore *seal_store)
{
    if (seal_store) {
		// printk("[rpcool] free_seal_store: freeing vma_cache\n");
        if (seal_store->vma_cache) {
            vfree(seal_store->vma_cache);
        }
		// printk("[rpcool] free_seal_store: freeing scope_id_allocator\n");
        ida_destroy(&seal_store->scope_id_allocator);
		// printk("[rpcool] free_seal_store: freeing seal_store\n");
        kfree(seal_store);
		// printk("[rpcool] free_seal_store: done\n");
    }
}
