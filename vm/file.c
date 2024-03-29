/* file.c: Implementation of memory backed file object (mmaped object). */

#include <string.h>
// clang-format off
#include "vm/vm.h"
#include "vm/uninit.h"
// clang-format on
#include "filesys/file.h"
#include "threads/malloc.h"
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
    return true;
  }

  struct lazy_load_args *args = (struct lazy_load_args *)uninit_page->aux;
  struct file *f = args->file;
  off_t ofs = args->ofs;
  size_t page_read_bytes = args->page_read_bytes;

  struct file_page *file_page = &page->file;
  filesys_lock_acquire();
  file_page->file = file_reopen(f);
  filesys_lock_release();
  file_page->ofs = ofs;
  file_page->page_read_bytes = page_read_bytes;
  file_page->type = type;

  return true;
}

/* Swap in the page by read contents from the file. */
static bool file_backed_swap_in(struct page *page, void *kva) {
  struct file_page *file_page = &page->file;

  struct file *file = file_page->file;
  const off_t ofs = file_page->ofs;
  const size_t page_read_bytes = file_page->page_read_bytes;
  const size_t page_zero_bytes = PGSIZE - page_read_bytes;

  if (file == NULL) {
    return false;
  }

  filesys_lock_acquire();
  file_read_at(file, kva, page_read_bytes, ofs);
  filesys_lock_release();
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
    filesys_lock_acquire();
    file_write_at(file, page->va, page_read_bytes, ofs);
    filesys_lock_release();
    pml4_set_dirty(pml4, page->va, false);
  }
  pml4_clear_page(pml4, page->va);

  return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void file_backed_destroy(struct page *page) {
  ASSERT(page != NULL);
  struct file_page *file_page = &page->file;

  struct file *f = file_page->file;
  off_t ofs = file_page->ofs;
  size_t page_read_bytes = file_page->page_read_bytes;

  filesys_lock_acquire();
  if (page->writable && pml4_get_page(page->owner->pml4, page->va) != NULL &&
      pml4_is_dirty(page->owner->pml4, page->va)) {
    file_write_at(f, page->va, page_read_bytes, ofs);
    pml4_set_dirty(page->owner->pml4, page->va, 0);
  }
  file_close(f);
  filesys_lock_release();
}

/* Do the mmap */
void *do_mmap(void *addr, size_t length, int writable, struct file *file,
              off_t offset) {
  void *start_addr = addr;

  filesys_lock_acquire();
  size_t read_bytes = file_length(file);
  filesys_lock_release();
  if (length <= read_bytes) {
    read_bytes = length;
  }
  size_t zero_bytes = PGSIZE - read_bytes % PGSIZE;
  size_t num_pages = 0;

  while (read_bytes > 0 || zero_bytes > 0) {
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    struct lazy_load_args *args =
        (struct lazy_load_args *)calloc(1, sizeof(struct lazy_load_args));
    filesys_lock_acquire();
    args->file = file_reopen(file);
    filesys_lock_release();
    args->ofs = offset;
    args->page_read_bytes = page_read_bytes;
    args->page_zero_bytes = page_zero_bytes;

    if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable,
                                        lazy_load_segment, (void *)args)) {
      filesys_lock_acquire();
      file_close(args->file);
      filesys_lock_release();
      free(args);
      return NULL;
    }

    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    addr += PGSIZE;
    offset += page_read_bytes;
    num_pages++;
  }

  struct mmap_info *minfo =
      (struct mmap_info *)calloc(1, sizeof(struct mmap_info));
  minfo->start_va = start_addr;
  minfo->num_pages = num_pages;
  list_push_back(&thread_current()->spt.mmap_table, &minfo->elem);

  return start_addr;
}

/* Do the munmap */
void do_munmap(void *addr) {
  struct thread *cur = thread_current();
  struct mmap_info *minfo = spt_find_mmap_info(&cur->spt, addr);
  if (minfo == NULL) {
    return;
  }

  for (size_t i = 0; i < minfo->num_pages; i++) {
    struct page *page = spt_find_page(&cur->spt, addr);
    spt_remove_page(&cur->spt, page);
    addr += PGSIZE;
  }

  list_remove(&minfo->elem);
  free(minfo);
}
