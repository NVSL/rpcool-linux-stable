#ifndef RPCOOL_SEAL_QUEUE_H
#define RPCOOL_SEAL_QUEUE_H

#include <linux/idr.h>
#include <linux/fs.h>
#include <linux/kfifo.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/atomic.h>

#define MAX_SCOPE_COUNT 4194304 // 2^22
struct SealEntry {
	size_t addr;
	size_t len;
	uint64_t nonce;
};

#define SEAL_ENTRY_NONCE_POSITION (sizeof(struct SealEntry) - sizeof(uint64_t))

struct SealStore {
	struct mutex seal_only_one_should_call_release_lock;
	struct file *f_metadata;
	atomic_t seal_counter;

	struct vm_area_struct **vma_cache;
	atomic_t vma_cache_size; // so we don't need to iterate all of the vma_cache
	struct ida scope_id_allocator;
};

int store_seal_at_index(struct SealStore *seal_store, size_t addr, size_t len,
			int index);
int reset_seal_nonce_at_index(struct SealStore *seal_store, int index);

// caller has to free the returned pointer
struct SealEntry *get_seal(struct SealStore *seal_store, ssize_t index);
uint64_t get_current_nonce(struct SealStore *seal_store, ssize_t index);
struct SealStore *initialize_seal_store(struct file *f_metadata);
void free_seal_store(struct SealStore *seal_store);
//returns value of release counter. 0 otherwise
uint64_t read_release_counter(struct SealStore *seal_store);
//returns 0 on success and -1 on failure
int reset_release_counter(struct SealStore *seal_store);

int atomic_max(atomic_t *v, int max);

#endif