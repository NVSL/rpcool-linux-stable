#ifndef _RPCOOL_KERNEL_H
#define _RPCOOL_KERNEL_H

#include "seal_queue.h"

#include <asm/io.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <crypto/hash_info.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/hugetlb.h>
#include <linux/kernel.h>
#include <linux/khugepaged.h>
#include <linux/list.h>
#include <linux/mempolicy.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/mm_types.h>
#include <linux/mman.h>
#include <linux/mmap_lock.h>
#include <linux/nodemask.h>
#include <linux/pkeys.h>
#include <linux/rmap.h>
#include <linux/sched.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>        // for kmalloc
#include <linux/stringhash.h>  // for full_name_hash
#include <linux/syscalls.h>
#include <linux/userfaultfd_k.h>

// helpers
void *pfn_to_virtual(unsigned long pfn);
void vma_to_phys(struct vm_area_struct *vma, unsigned long vaddr);
void print_all_user_addr(struct vm_area_struct *vma, size_t size,
                         unsigned long user_addr);

const char * get_path_user(const char __user *path);
char *concat_paths(const char *base, const char *suffix);
const char *concat_paths_user(const char __user *base, const char *suffix);

const char *concat_connection_paths_user(const char __user *base,
                                         long connection_id,
                                         const char *suffix);

const char *concat_dev_connection_paths_user(const char* dev_prefix, const char __user *base,
                                         long connection_id, const char *suffix);

unsigned long rpcool_do_mmap(struct task_struct *target_process,
                             struct file *file, unsigned long addr,
                             unsigned long len, unsigned long prot,
                             unsigned long flags, unsigned long pgoff,
                             unsigned long *populate, struct list_head *uf);

size_t read_file_size(struct file *file);

long copy_string_from_user(char *kernel_buffer, size_t buffer_size, const char __user *user_string);

int init_hash_algorithm(void);
int validate_signature(const unsigned char __user *user_signature, const unsigned char *key, size_t key_size, uint64_t index, uint64_t nonce);

// Hash table entries

struct shared_heap_entry {
  char *dev_prefix_path;
  char *path;
  struct file *shared_heap;
  struct hlist_node hnode;
};

struct connection_entry {
  char *path;
  struct file *metadata;
  struct file *private_heap;
  struct SealStore * seal_store;
  struct hlist_node hnode;
};

#define SHARED_HEAP_TABLE_BITS 10  // A table of 2^10 entries
#define CONNECTION_TABLE_BITS 10     // A table of 2^10 entries

#define HMAC_KEY "8NQEL3eZmLj7IgYwkeKnzLtE+qzwEJu9"

#endif  //_RPCOOL_KERNEL_H