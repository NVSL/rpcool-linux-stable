#include "seal_queue.h"

#include <linux/err.h>

#define KEY_POS 0
#define Q_SIZE_POS 48
#define ENTRIES_START_POS Q_SIZE_POS + 8

#define HMAC_KEY2 "8NQEL3eZmLj7IgYwkeKnzLtE+qzwEJu9"


int get_next_free_element(struct SealStore * seal_store) {
    int next_free_element;
    if (!kfifo_get(&seal_store->free_list, &next_free_element)) {
        return -1;
    }
    return next_free_element;
}

uint64_t get_current_nonce(struct SealStore* seal_store, ssize_t index) {
    loff_t pos;
    ssize_t result;
    uint64_t nonce;

    // Calculate the position of the nonce in the file
    pos = ENTRIES_START_POS + index * sizeof(struct SealEntry) + SEAL_ENTRY_NONCE_POSITION;

    // Read only the nonce part
    result = kernel_read(seal_store->f_metadata, &nonce, sizeof(nonce), &pos);
    if (result < 0) {
        pr_err("[rpcool] Error reading nonce from queue: %zd\n", result);
        return ERR_PTR(result);
    }

    return nonce;
}


int store_seal(struct SealStore* seal_store, size_t addr, size_t len) {
    loff_t pos;
    ssize_t result;
    int next_free_element;
    struct SealEntry entry = {
        .addr = addr,
        .len = len,
    };

    pr_info("[rpcool] enqueueing a seal at addr = %lu, len = %lu\n", addr, len);
    pr_info("[rpcool] aquiring the lock\n");
    
    mutex_lock(&seal_store->lock);
    next_free_element = get_next_free_element(seal_store);
    mutex_unlock(&seal_store->lock);
    
    if (next_free_element == -1) {
        pr_err("[rpcool] seal store is full\n");
        return -ENOMEM;
    }
    pr_info("[rpcool] next free element is at @ %d\n", next_free_element);

    entry.nonce = get_current_nonce(seal_store, next_free_element); // read & incremnt nonce in memory
    entry.nonce++;

    pos = ENTRIES_START_POS + next_free_element * sizeof(struct SealEntry);
    result = kernel_write(seal_store->f_metadata, &entry, sizeof(struct SealEntry), &pos); // also stores the new nonce
    if (result < 0) {
        pr_err("[rpcool] Error writing entry to queue: %zd\n", result);
        return result;
    }

    
    return next_free_element;
}

struct SealStore * initialize_seal_store(struct file *f_metadata) {
    struct SealStore *seal_store;
    loff_t pos;
    uint64_t store_size = MAX_QUEUE_LEN;
    ssize_t result;
    int i;

    pr_info("[rpcool] initializing seal store\n");

    seal_store = kmalloc(sizeof(struct SealStore), GFP_KERNEL);
    if (!seal_store) {
        pr_err("[rpcool] Error allocating memory for seal store\n");
        return ERR_PTR(-ENOMEM);
    }

    seal_store->f_metadata = f_metadata;
    INIT_KFIFO(seal_store->free_list);
    mutex_init(&seal_store->lock);

    // write size to file
    pos = Q_SIZE_POS;
    result = kernel_write(f_metadata, &store_size, sizeof(store_size), &pos);
    if (result < 0) {
        pr_err("[rpcool] Error writing queue size to file while initializing the seal store: %zd\n", result);
        kfree(seal_store);
        return ERR_PTR(result);
    }

    for (i = 0; i < store_size; i++) {
        if (!kfifo_put(&seal_store->free_list, i)) {
            kfree(seal_store);
            pr_err("[rpcool] Error initializing the free list. Could not initialize the seal store's free list with item [%d]\n", i);
            return ERR_PTR(-ENOMEM);
        }
    }

    return seal_store;
}

struct SealEntry * get_seal(struct SealStore* seal_store, ssize_t index) {
    loff_t pos;
    ssize_t result;

    struct SealEntry *entry = kmalloc(sizeof(struct SealEntry), GFP_KERNEL);
    if (!entry) {
        pr_err("[rpcool] Error allocating memory for seal entry\n");
        return ERR_PTR(-ENOMEM);
    }
    pos = ENTRIES_START_POS + index * sizeof(struct SealEntry);
    result = kernel_read(seal_store->f_metadata, entry, sizeof(struct SealEntry), &pos);
    if (result < 0) {
        pr_err("[rpcool] Error reading entry from queue: %zd\n", result);
        return ERR_PTR(result);
    }
    return entry;
}


int release_seal(struct SealStore* seal_store, ssize_t index) {
    loff_t pos;
    ssize_t result;
    struct SealEntry *entry;

    pr_info("[rpcool] releasing seal at index = %zd\n", index);

    entry = get_seal(seal_store, index);
    if (IS_ERR(entry)) {
        pr_err("[rpcool] release: Error getting seal entry at index = %zd\n", index);
        return PTR_ERR(entry);
    }
    //possibly perform crypto HMAC check here

    entry->addr = 0;
    entry->len = 0;

    pos = ENTRIES_START_POS + index * sizeof(struct SealEntry);
    result = kernel_write(seal_store->f_metadata, entry, sizeof(struct SealEntry), &pos);
    if (result < 0) {
        pr_err("[rpcool] release: Error zeroing out the entry in the seal store: %zd\n", result);
        return result;
    }

    mutex_lock(&seal_store->lock);
    if (!kfifo_put(&seal_store->free_list, index)) {
            pr_err("[rpcool] release: Error adding the index to the free list\n");
            return -ENOMEM;
        }
    mutex_unlock(&seal_store->lock);

    kfree(entry);
    return 0;
}


/*
ssize_t enqueue_seal(struct SealStore* seal_store, size_t addr, size_t len);
    loff_t pos;
    uint64_t q_head, q_tail;
    ssize_t result;

    // Read current queue head and tail
    pos = Q_HEAD_POS;
    result = kernel_read(f_file, &q_head, sizeof(q_head), &pos);
    if (result < 0) return result;

    pos = Q_TAIL_POS;
    result = kernel_read(f_file, &q_tail, sizeof(q_tail), &pos);
    if (result < 0) return result;

    // Check if the queue is full
    if ((q_tail + 1) % MAX_QUEUE_LEN == q_head) {
        pr_err("Queue is full\n");
        return -ENOMEM;
    }

    // Write the entry at the current tail position
    pos = ENTRIES_START_POS + q_tail * sizeof(struct SealEntry);
    result = kernel_write(f_file, entry, sizeof(struct SealEntry), &pos);
    if (result < 0) {
        pr_err("Error writing entry to queue: %zd\n", result);
        return result;
    }

    // Update the tail
    q_tail = (q_tail + 1) % MAX_QUEUE_LEN;
    pos = Q_TAIL_POS;
    result = kernel_write(f_file, &q_tail, sizeof(q_tail), &pos);
    if (result < 0) {
        pr_err("Error updating queue tail: %zd\n", result);
        return result;
    }

    pr_info("Successfully enqueued an entry\n");
    return result;
}

ssize_t initialize_queue(struct file *f_file) {
    loff_t pos;
    uint64_t store_size = MAX_QUEUE_LEN;
    uint64_t q_head = 0;
    uint64_t q_tail = 0;
    ssize_t result;

    // Write queue size
    pos = Q_SIZE_POS;
    result = kernel_write(f_file, &store_size, sizeof(store_size), &pos);
    if (result < 0) {
        pr_err("Error writing queue size: %zd\n", result);
        return result;
    }

    // Write queue head
    pos = Q_HEAD_POS;
    result = kernel_write(f_file, &q_head, sizeof(q_head), &pos);
    if (result < 0) {
        pr_err("Error writing queue head: %zd\n", result);
        return result;
    }

    // Write queue tail
    pos = Q_TAIL_POS;
    result = kernel_write(f_file, &q_tail, sizeof(q_tail), &pos);
    if (result < 0) {
        pr_err("Error writing queue tail: %zd\n", result);
        return result;
    }

    pr_info("Queue initialized successfully\n");
    return result;
}

*/