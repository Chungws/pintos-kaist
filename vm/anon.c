/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include <bitmap.h>
#include <string.h>

#include "devices/disk.h"
#include "threads/mmu.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
// clang-format off
#include "vm/vm.h"
#include "vm/uninit.h"
// clang-format on

#define SECTOR_PER_PAGE (PGSIZE / DISK_SECTOR_SIZE)
struct swap_table {
  struct bitmap *table;
  struct lock lock;
};
static struct swap_table swap_table;

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in(struct page *page, void *kva);
static bool anon_swap_out(struct page *page);
static void anon_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
    .swap_in = anon_swap_in,
    .swap_out = anon_swap_out,
    .destroy = anon_destroy,
    .type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void vm_anon_init(void) {
  /* TODO: Set up the swap_disk. */
  swap_disk = disk_get(1, 1);
  size_t num_bits = (size_t)disk_size(swap_disk) / SECTOR_PER_PAGE;
  swap_table.table = bitmap_create(num_bits);
  lock_init(&swap_table.lock);
}

/* Initialize the file mapping */
bool anon_initializer(struct page *page, enum vm_type type, void *kva) {
  /* Set up the handler */
  page->operations = &anon_ops;
  struct uninit_page *uninit_page = &page->uninit;
  memset((void *)uninit_page, 0, sizeof(struct uninit_page));

  struct anon_page *anon_page = &page->anon;
  anon_page->swap_table_index = -1;
  anon_page->type = type;
  return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool anon_swap_in(struct page *page, void *kva) {
  struct anon_page *anon_page = &page->anon;
  int idx = anon_page->swap_table_index;
  lock_acquire(&swap_table.lock);
  if (idx < 0 || bitmap_test(swap_table.table, idx) == false) {
    lock_release(&swap_table.lock);
    return false;
  }

  for (int i = 0; i < SECTOR_PER_PAGE; i++) {
    disk_sector_t sector = idx * SECTOR_PER_PAGE + i;
    void *memory = kva + DISK_SECTOR_SIZE * i;
    disk_read(swap_disk, sector, memory);
  }
  bitmap_set(swap_table.table, idx, false);
  anon_page->swap_table_index = -1;
  lock_release(&swap_table.lock);

  return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool anon_swap_out(struct page *page) {
  struct anon_page *anon_page = &page->anon;
  lock_acquire(&swap_table.lock);
  size_t idx = bitmap_scan(swap_table.table, 0, 1, false);

  if (idx == BITMAP_ERROR) {
    lock_release(&swap_table.lock);
    return false;
  }

  for (int i = 0; i < SECTOR_PER_PAGE; i++) {
    disk_sector_t sector = idx * SECTOR_PER_PAGE + i;
    void *memory = page->frame->kva + DISK_SECTOR_SIZE * i;
    disk_write(swap_disk, sector, memory);
  }
  bitmap_set(swap_table.table, idx, true);
  pml4_clear_page(page->owner->pml4, page->va);
  lock_release(&swap_table.lock);

  anon_page->swap_table_index = idx;
  return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void anon_destroy(struct page *page) {
  struct anon_page *anon_page = &page->anon;
  int idx = anon_page->swap_table_index;
  if (idx < 0) {
    return;
  }

  lock_acquire(&swap_table.lock);
  if (bitmap_test(swap_table.table, idx) == true) {
    bitmap_set(swap_table.table, idx, false);
  }
  lock_release(&swap_table.lock);

  memset((void *)anon_page, 0, sizeof(struct anon_page));
}
