#ifndef RPCOOL_SEAL_QUEUE_H
#define RPCOOL_SEAL_QUEUE_H
#include <linux/fs.h>
#include <linux/kfifo.h>
#include <linux/mutex.h>
#include <linux/types.h>

#define MAX_QUEUE_LEN 1024  // Adjust according to your maximum queue length


struct SealEntry
{
    size_t addr;
    size_t len;
    uint64_t nonce;
};

#define SEAL_ENTRY_NONCE_POSITION (sizeof(struct SealEntry) - sizeof(uint64_t))

struct SealStore
{
    DECLARE_KFIFO(free_list, int, MAX_QUEUE_LEN);
    struct mutex lock;
    struct file *f_metadata;
};

// struct SealFreeList; update store_seal return type comment

//return index of the seal entry or error (negative value) otherwise
//return type == SealStore.kfifo item type
int store_seal(struct SealStore* seal_store, size_t addr, size_t len);
// caller has to free the returned pointer
struct SealEntry * get_seal(struct SealStore* seal_store, ssize_t index);
uint64_t get_current_nonce(struct SealStore* seal_store, ssize_t index);
int release_seal(struct SealStore* seal_store, ssize_t index);
struct SealStore * initialize_seal_store(struct file *f_metadata);

#endif