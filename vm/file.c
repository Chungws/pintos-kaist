/* file.c: Implementation of memory backed file object (mmaped object). */

#include <string.h>
// clang-format off
#include "vm/vm.h"
#include "vm/uninit.h"
// clang-format on
#include "filesys/file.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "userprog/process.h"

static bool file_backed_swap_in(struct page *page, void *kva);
static bool file_backed_swap_out(struct page *page);
static void file_backed_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
    .swap_in = file_backed_swap_in,
    .swap_out = file_backed_swap_out,
    .destroy = file_backed_destroy,
    .type = VM_FILE,
};

/* The initializer of file vm */
void vm_file_init(void) {}

/* Initialize the file backed page */
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva) {
  /* Set up the handler */
  page->operations = &file_ops;
  struct uninit_page *uninit_page = &page->uninit;
  if (uninit_page->aux == NULL) {
    memset((void *)uninit_page, 0, sizeof(struct uninit_page));
    return true;
  }

  struct lazy_load_args *args = (struct lazy_load_args *)uninit_page->aux;
  struct file *f = args->file;
  off_t ofs = args->ofs;
  size_t page_read_bytes = args->page_read_bytes;
  void *start_addr = args->start_addr;

  memset((void *)uninit_page, 0, sizeof(struct uninit_page));

  struct file_page *file_page = &page->file;
  file_page->file = f;
  file_page->ofs = ofs;
  file_page->page_read_bytes = page_read_bytes;
  file_page->type = type;
  file_page->start_addr = start_addr;

  return true;
}

/* Swap in the page by read contents from the file. */
static bool file_backed_swap_in(struct page *page, void *kva) {
  struct file_page *file_page = &page->file;

  uint64_t *pml4 = thread_current()->pml4;

  struct file *file = file_page->file;
  const off_t ofs = file_page->ofs;
  const size_t page_read_bytes = file_page->page_read_bytes;
  const size_t page_zero_bytes = PGSIZE - page_read_bytes;

  file_seek(file, ofs);
  if (page_read_bytes != (size_t)file_read(file, kva, page_read_bytes)) {
    return false;
  }
  memset(kva + page_read_bytes, 0, page_zero_bytes);
  return true;
}

/* Swap out the page by writeback contents to the file. */
static bool file_backed_swap_out(struct page *page) {
  struct file_page *file_page = &page->file;

  uint64_t *pml4 = page->owner->pml4;

  struct file *file = file_page->file;
  const off_t ofs = file_page->ofs;
  const size_t page_read_bytes = file_page->page_read_bytes;

  if (pml4_is_dirty(pml4, page->va)) {
    file_seek(file, ofs);
    file_write(file, page->va, page_read_bytes);
    pml4_set_dirty(pml4, page->va, false);
  }
  pml4_clear_page(pml4, page->va);

  return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void file_backed_destroy(struct page *page) {
  ASSERT(page != NULL);
  struct file_page *file_page = &page->file;

  struct thread *cur = thread_current();

  struct file *f = file_page->file;
  off_t ofs = file_page->ofs;
  size_t page_read_bytes = file_page->page_read_bytes;

  if (pml4_get_page(page->owner->pml4, page->va) != NULL) {
    if (pml4_is_dirty(page->owner->pml4, page->va)) {
      file_write_at(f, page->va, page_read_bytes, ofs);
      pml4_set_dirty(page->owner->pml4, page->va, 0);
    }
    pml4_clear_page(page->owner->pml4, page->va);
  }

  memset((void *)file_page, 0, sizeof(struct file_page));
}

/* Do the mmap */
void *do_mmap(void *addr, size_t length, int writable, struct file *file,
              off_t offset) {
  void *start_addr = addr;
  struct file *mapped_file = file_reopen(file);

  size_t read_bytes = file_length(file);
  if (length <= read_bytes) {
    read_bytes = length;
  }
  size_t zero_bytes = PGSIZE - read_bytes % PGSIZE;
  bool first_page = true;

  while (read_bytes > 0 || zero_bytes > 0) {
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    struct lazy_load_args *args =
        (struct lazy_load_args *)calloc(1, sizeof(struct lazy_load_args));
    enum vm_type type = VM_FILE;
    if (first_page) {
      type |= VM_MMAP_ADDR;
    }
    args->file = mapped_file;
    args->ofs = offset;
    args->page_read_bytes = page_read_bytes;
    args->page_zero_bytes = page_zero_bytes;
    args->start_addr = start_addr;

    if (!vm_alloc_page_with_initializer(type, addr, writable, lazy_load_segment,
                                        (void *)args)) {
      free(args);
      return NULL;
    }

    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    addr += PGSIZE;
    offset += page_read_bytes;
    first_page = false;
  }
  return start_addr;
}

/* Do the munmap */
void do_munmap(void *addr) {
  struct thread *cur = thread_current();
  int mmap_count = 0;
  while (true) {
    struct page *page = spt_find_page(&cur->spt, addr);

    if (page == NULL) {
      break;
    }

    enum vm_type pg_type = VM_TYPE(page->operations->type);
    bool is_vm_file = (pg_type == VM_FILE);
    bool is_vm_uninit_file =
        (pg_type == VM_UNINIT) && (VM_TYPE(page->uninit.type) == VM_FILE);

    if (!is_vm_file && !is_vm_uninit_file) {
      break;
    }

    if ((is_vm_file && (page->file.type & VM_MMAP_ADDR)) ||
        (is_vm_uninit_file && (page->uninit.type & VM_MMAP_ADDR))) {
      ++mmap_count;
    }

    if (mmap_count == 2) {
      // Found another mmapped address, should stop here.
      break;
    }
    spt_remove_page(&cur->spt, page);
    addr += PGSIZE;
  }
}
