/* file.c: Implementation of memory backed file object (mmaped object). */

#include <string.h>
// clang-format off
#include "vm/vm.h"
#include "vm/uninit.h"
// clang-format on
#include "filesys/file.h"
#include "threads/mmu.h"

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

  struct file_page *file_page = &page->file;
  file_page->file = f;
  file_page->ofs = ofs;
  file_page->page_read_bytes = page_read_bytes;

  memset((void *)uninit_page, 0, sizeof(struct uninit_page));
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
  if (page_zero_bytes != (size_t)file_read(file, kva, page_read_bytes)) {
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
  memset((void *)file_page, 0, sizeof(struct file_page));
}

/* Do the mmap */
void *do_mmap(void *addr, size_t length, int writable, struct file *file,
              off_t offset) {}

/* Do the munmap */
void do_munmap(void *addr) {}
