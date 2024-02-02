#include <linux/slab.h>    // For kmalloc and kfree
#include <linux/string.h>  // For strcat and strncat functions

#include "rpcool.h"

void *pfn_to_virtual(unsigned long pfn) {
  struct page *page;
  void *virtual_address;

  page = pfn_to_page(pfn);               // Retrieve the struct page descriptor
  virtual_address = page_address(page);  // Get the virtual address

  return virtual_address;
}

void vma_to_phys(struct vm_area_struct *vma, unsigned long vaddr) {
  struct page *page;
  unsigned long paddr = 0;
  unsigned long pfn = 0;

  // Find the page associated with the given virtual address
  page = follow_page(vma, vaddr, FOLL_WRITE);
  if (IS_ERR(page)) {
    long error_code = PTR_ERR(page);
    printk("[rpcool] could not follow page @%lu returned error %ld\n", vaddr,
           error_code);
    return;
  }
  if (page) {
    // Convert the virtual address to physical address using virt_to_phys()
    paddr = page_to_phys(page);
    pfn = page_to_pfn(page);
    printk(
        "[rpcool] vma vaddr: %lu, pfn: %lu, paddr: %pa, long_addr: %lu, "
        "reverse_pfn: %px\n",
        vaddr, pfn, &paddr, paddr, pfn_to_virtual(pfn));
    put_page(page);
  } else {
    printk("[rpcool] could not follow the page @%lu\n", vaddr);
  }
}

// Print the virtual and physical addresses of the user space VMA pages
void print_all_user_addr(struct vm_area_struct *vma, size_t size,
                         unsigned long user_addr) {
  unsigned long i;
  for (i = 0; i < size; i += PAGE_SIZE) {
    vma_to_phys(vma, (unsigned long)user_addr + i);
  }
}

char *concat_paths(const char *base, const char *suffix) {
  char *result = kmalloc(strlen(base) + strlen(suffix) + 2, GFP_KERNEL);
  strcpy(result, base);
  strcat(result, "/");
  strcat(result, suffix);
  return result;
}

const char * get_path_user(const char __user *path) {
  char * result;
  struct filename *fname = getname(path);
  if (IS_ERR(fname)) {
      return ERR_CAST(fname);
  }

  result = kmalloc(strlen(fname->name) + 1, GFP_KERNEL);  // +1 for null terminator
  if (result) {
      strcpy(result, fname->name);
  }
  putname(fname);
  return result;
}


const char *concat_paths_user(const char __user *base, const char *suffix) {
  struct filename *fname = getname(base);
  char *new_path = concat_paths(fname->name, suffix);
  putname(fname);
  // printk("concatenated path is %s\n", new_path);
  return new_path;
}

const char *long_to_string(long number) {
  char *result = kmalloc(21, GFP_KERNEL);
  snprintf(result, sizeof(result), "%ld", number);
  return result;
}

const char *concat_connection_paths_user(const char __user *base,
                                         long connection_id,
                                         const char *suffix) {
  const char *result;
  const char *connection_id_string = long_to_string(connection_id);
  const char *conn_path = concat_paths_user(base, connection_id_string);
  kfree(connection_id_string);

  result = concat_paths(conn_path, suffix);
  kfree(conn_path);

  // printk("concatenated connection path is %s\n", result);

  return result;
}



const char *concat_dev_connection_paths_user(const char* dev_prefix, const char __user *base,
                                         long connection_id, const char *suffix) {

  printk("[rpcool] concat_dev_connection_paths_user called\n");
  const char *tmp = concat_connection_paths_user(base, connection_id, suffix);
  printk("[rpcool] tmp is %s\n", tmp);
  const char *result = concat_paths(dev_prefix, tmp);
  printk("[rpcool] result is %s\n", result);
  kfree(tmp);
  return result;
}


size_t read_file_size(struct file *file) {
    return  i_size_read(file->f_inode);
}

long copy_string_from_user(char *kernel_buffer, size_t buffer_size, const char __user *user_string) {
    long copied;

    if (!user_string)
        return -EINVAL;

    copied = strncpy_from_user(kernel_buffer, user_string, buffer_size);
    if (copied < 0 || copied == buffer_size)
        return -EFAULT;

    return 0; // Success
}