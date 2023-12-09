/* vm.c: Generic interface for virtual memory objects. */

#include "vm/vm.h"

#include <string.h>

#include "threads/malloc.h"
#include "threads/mmu.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "vm/inspect.h"

struct frame_list {
  struct list list;
  struct lock lock;
};

static struct frame_list lru_list;

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void) {
  vm_anon_init();
  vm_file_init();
#ifdef EFILESYS /* For project 4 */
  pagecache_init();
#endif
  register_inspect_intr();
  /* DO NOT MODIFY UPPER LINES. */
  /* TODO: Your code goes here. */
  list_init(&lru_list.list);
  lock_init(&lru_list.lock);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type page_get_type(struct page *page) {
  int ty = VM_TYPE(page->operations->type);
  switch (ty) {
    case VM_UNINIT:
      return VM_TYPE(page->uninit.type);
    default:
      return ty;
  }
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage,
                                    bool writable, vm_initializer *init,
                                    void *aux) {
  ASSERT(VM_TYPE(type) != VM_UNINIT)

  struct supplemental_page_table *spt = &thread_current()->spt;

  /* Check wheter the upage is already occupied or not. */
  if (spt_find_page(spt, upage) == NULL) {
    /* TODO: Create the page, fetch the initialier according to the VM type,
     * TODO: and then create "uninit" page struct by calling uninit_new. You
     * TODO: should modify the field after calling the uninit_new. */
    struct page *pg = (struct page *)calloc(1, sizeof(struct page));
    if (pg == NULL) {
      goto err;
    }
    bool (*page_initializer)(struct page *, enum vm_type, void *kva);

    switch (VM_TYPE(type)) {
      case VM_ANON:
        page_initializer = &anon_initializer;
        break;
      case VM_FILE:
        page_initializer = &file_backed_initializer;
        break;
    }

    uninit_new(pg, upage, init, type, aux, page_initializer);
    pg->owner = thread_current();
    pg->writable = writable;
    pg->do_not_swap_out = false;

    /* TODO: Insert the page into the spt. */
    if (!spt_insert_page(spt, pg)) {
      vm_dealloc_page(pg);
      goto err;
    }

    return true;
  }
err:
  return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *spt_find_page(struct supplemental_page_table *spt, void *va) {
  struct page *page = NULL;
  /* TODO: Fill this function. */
  if (spt->table.elem_cnt == 0) {
    return page;
  }

  struct page pg;
  pg.va = pg_round_down(va);

  struct hash_elem *e = hash_find(&spt->table, &pg.hash_elem);

  if (e != NULL) {
    page = hash_entry(e, struct page, hash_elem);
  }

  return page;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt, struct page *page) {
  int succ = false;
  /* TODO: Fill this function. */
  struct hash_elem *e = hash_insert(&spt->table, &page->hash_elem);
  if (e == NULL) {
    succ = true;
  }

  return succ;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page) {
  ASSERT(hash_find(&spt->table, &page->hash_elem) != NULL);
  hash_delete(&spt->table, &page->hash_elem);
  vm_remove_page(page);
}

/* Get the struct frame, that will be evicted. */
static struct frame *vm_get_victim(void) {
  struct frame *victim = NULL;
  struct frame *victim_candidate = NULL;
  bool found_candidate = false;
  /* TODO: The policy for eviction is up to you. */

  lock_acquire(&lru_list.lock);
  if (!list_empty(&lru_list.list)) {
    for (struct list_elem *e = list_begin(&lru_list.list);
         e != list_end(&lru_list.list); e = list_next(e)) {
      struct frame *fr = list_entry(e, struct frame, elem);

      // if (fr->page == NULL) {
      //   continue;
      // }
      uint64_t *pml4 = fr->page->owner->pml4;

      if (fr->page->do_not_swap_out) {
        continue;
      }
      if (!found_candidate) {
        victim_candidate = fr;
        found_candidate = true;
      }

      if (pml4_is_accessed(pml4, fr->page->va)) {
        pml4_set_accessed(pml4, fr->page->va, false);
      } else {
        victim = fr;
        break;
      }
    }
    if (victim == NULL) {
      ASSERT(victim_candidate != NULL);
      victim = victim_candidate;
    }
    list_remove(&victim->elem);
    list_push_back(&lru_list.list, &victim->elem);
  }
  lock_release(&lru_list.lock);

  return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *vm_evict_frame(void) {
  struct frame *victim = vm_get_victim();
  /* TODO: swap out the victim and return the evicted frame. */
  struct page *page = victim->page;
  if (page != NULL && swap_out(page)) {
    victim->page->frame = NULL;
    victim->page = NULL;
    return victim;
  }

  return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *vm_get_frame(void) {
  struct frame *frame = NULL;
  /* TODO: Fill this function. */
  void *kva = palloc_get_page(PAL_USER);
  if (kva != NULL) {
    frame = (struct frame *)calloc(1, sizeof(struct frame));
    frame->kva = kva;
    lock_acquire(&lru_list.lock);
    list_push_back(&lru_list.list, &frame->elem);
    lock_release(&lru_list.lock);
  } else {
    frame = vm_evict_frame();
  }

  ASSERT(frame != NULL);
  ASSERT(frame->page == NULL);
  return frame;
}

/* Growing the stack. */
static void vm_stack_growth(void *addr) {
  if (vm_alloc_page(VM_ANON | VM_STACK, addr, 1)) {
    vm_claim_page(addr);
    thread_current()->stack_bottom -= PGSIZE;
  }
}

/* Handle the fault on write_protected page */
static bool vm_handle_wp(struct page *page UNUSED) {}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool user,
                         bool write, bool not_present) {
  struct supplemental_page_table *spt = &thread_current()->spt;
  struct page *page = NULL;
  /* TODO: Validate the fault */
  /* TODO: Your code goes here */
  if (addr == NULL || is_kernel_vaddr(addr) || !not_present) {
    return false;
  }

  if (!vm_claim_page(addr)) {
    void *rsp_stack =
        is_kernel_vaddr(f->rsp) ? thread_current()->rsp_stack : f->rsp;
    if (rsp_stack - 8 <= addr && USER_STACK - 0x100000 <= addr &&
        addr <= USER_STACK) {
      vm_stack_growth(thread_current()->stack_bottom - PGSIZE);
      return true;
    }
    return false;
  }

  page = spt_find_page(spt, addr);
  if (write && !page->writable) {
    return false;
  }
  return true;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page) {
  destroy(page);
  free(page);
}

void vm_remove_page(struct page *page) {
  struct frame *fr = page->frame;
  vm_dealloc_page(page);
  if (fr != NULL) {
    lock_acquire(&lru_list.lock);
    list_remove(&fr->elem);
    free(fr);
    lock_release(&lru_list.lock);
  }
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va) {
  struct page *page = NULL;
  /* TODO: Fill this function */
  struct supplemental_page_table *spt = &thread_current()->spt;
  page = spt_find_page(spt, va);
  if (page == NULL) {
    return false;
  }

  return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool vm_do_claim_page(struct page *page) {
  struct frame *frame = vm_get_frame();

  /* Set links */
  frame->page = page;
  page->frame = frame;

  /* TODO: Insert page table entry to map page's VA to frame's PA. */
  if (pml4_get_page(thread_current()->pml4, page->va) != NULL ||
      !pml4_set_page(thread_current()->pml4, page->va, frame->kva,
                     page->writable)) {
    palloc_free_page(frame->kva);
    free(frame);
    return false;
  }
  return swap_in(page, frame->kva);
}

/* Initialize new supplemental page table */
uint64_t supplemental_page_table_hash(const struct hash_elem *e,
                                      void *aux UNUSED) {
  struct page *pg = hash_entry(e, struct page, hash_elem);
  return hash_bytes(&pg->va, sizeof(pg->va));
}

bool supplemental_page_table_hash_less_func(const struct hash_elem *a,
                                            const struct hash_elem *b,
                                            void *aux UNUSED) {
  struct page *pg_a = hash_entry(a, struct page, hash_elem);
  struct page *pg_b = hash_entry(b, struct page, hash_elem);

  return pg_a->va < pg_b->va;
}

void supplemental_page_table_init(struct supplemental_page_table *spt) {
  hash_init(&spt->table, &supplemental_page_table_hash,
            &supplemental_page_table_hash_less_func, NULL);
}

bool handle_copy_uninit_page(struct page *src) {
  struct uninit_page *uninit = &src->uninit;
  struct lazy_load_args *src_aux = (struct lazy_load_args *)uninit->aux;

  struct lazy_load_args *aux =
      (struct lazy_load_args *)calloc(1, sizeof(struct lazy_load_args));
  if (aux == NULL) {
    return false;
  }

  if (VM_TYPE(uninit->type) == VM_FILE) {
    aux->start_addr = src_aux->start_addr;
  }

  if (uninit->type & VM_MMAP_ADDR) {
    aux->file = file_reopen(src_aux->file);
  } else {
    aux->file = NULL;
  }

  aux->ofs = src_aux->ofs;
  aux->page_read_bytes = src_aux->page_read_bytes;
  aux->page_zero_bytes = src_aux->page_zero_bytes;

  return vm_alloc_page_with_initializer(uninit->type, src->va, src->writable,
                                        uninit->init, aux);
}

bool handle_copy_anon_page(struct page *src) {
  if (!vm_alloc_page(src->operations->type, src->va, src->writable)) {
    return false;
  }
  struct page *dst = spt_find_page(&thread_current()->spt, src->va);
  if (dst == NULL) {
    return false;
  }

  if (!vm_do_claim_page(dst)) {
    return false;
  }

  dst->anon.swap_table_index = -1;
  dst->anon.type = src->anon.type;
  dst->do_not_swap_out = src->do_not_swap_out;

  uint64_t *pml4_src = src->owner->pml4;
  uint64_t *pml4_dst = dst->owner->pml4;
  if (pml4_is_dirty(pml4_src, src->va)) {
    pml4_set_dirty(pml4_dst, dst->va, true);
  }

  if (pml4_is_accessed(pml4_src, src->va)) {
    pml4_set_accessed(pml4_dst, dst->va, true);
  }

  ASSERT(dst->frame != NULL);
  memcpy(dst->frame->kva, src->frame->kva, PGSIZE);
  return true;
}

bool handle_copy_file_page(struct page *src) {
  if (!vm_alloc_page(src->operations->type, src->va, src->writable)) {
    return false;
  }
  struct page *dst = spt_find_page(&thread_current()->spt, src->va);
  if (dst == NULL) {
    return false;
  }

  if (!vm_do_claim_page(dst)) {
    return false;
  }

  dst->do_not_swap_out = src->do_not_swap_out;

  struct file_page *src_file_page = &src->file;
  struct file_page *dst_file_page = &dst->file;

  if (dst_file_page->type & VM_MMAP_ADDR) {
    dst_file_page->file = file_reopen(src_file_page->file);
  }

  dst_file_page->start_addr = src_file_page->start_addr;
  dst_file_page->ofs = src_file_page->ofs;
  dst_file_page->page_read_bytes = src_file_page->page_read_bytes;
  dst_file_page->type = src_file_page->type;

  uint64_t *pml4_src = src->owner->pml4;
  uint64_t *pml4_dst = dst->owner->pml4;
  if (pml4_is_dirty(pml4_src, src->va)) {
    pml4_set_dirty(pml4_dst, dst->va, true);
  }

  if (pml4_is_accessed(pml4_src, src->va)) {
    pml4_set_accessed(pml4_dst, dst->va, true);
  }

  ASSERT(dst->frame != NULL);
  memcpy(dst->frame->kva, src->frame->kva, PGSIZE);
  return true;
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst,
                                  struct supplemental_page_table *src) {
  struct hash_iterator i;
  hash_first(&i, &src->table);
  bool result = false;

  while (hash_next(&i)) {
    struct page *src_pg = hash_entry(hash_cur(&i), struct page, hash_elem);
    enum vm_type type = src_pg->operations->type;

    switch (VM_TYPE(type)) {
      case VM_UNINIT:
        if (!handle_copy_uninit_page(src_pg)) {
          return false;
        }
        break;
      case VM_ANON:
        if (!handle_copy_anon_page(src_pg)) {
          return false;
        }
        break;
      case VM_FILE:
        if (!handle_copy_file_page(src_pg)) {
          return false;
        }
        break;
    }
  }

  hash_first(&i, &dst->table);
  while (hash_next(&i)) {
    struct page *dst_pg = hash_entry(hash_cur(&i), struct page, hash_elem);
    enum vm_type type = dst_pg->operations->type;

    switch (VM_TYPE(type)) {
      case VM_UNINIT: {
        enum vm_type uninit_type = dst_pg->uninit.type;
        struct lazy_load_args *args =
            (struct lazy_load_args *)dst_pg->uninit.aux;

        if (VM_TYPE(uninit_type) == VM_ANON) {
          args->file = thread_current()->running_file;
        } else if (VM_TYPE(uninit_type) == VM_FILE &&
                   !(uninit_type & VM_MMAP_ADDR)) {
          struct page *start_addr_pg = spt_find_page(dst, args->start_addr);
          enum vm_type pg_type = VM_TYPE(start_addr_pg->operations->type);

          if (pg_type == VM_FILE) {
            args->file = start_addr_pg->file.file;
          } else if (pg_type == VM_UNINIT) {
            struct lazy_load_args *start_addr_args =
                (struct lazy_load_args *)start_addr_pg->uninit.aux;
            args->file = start_addr_args->file;
          }
        }
        break;
      }
      case VM_ANON:
        break;
      case VM_FILE: {
        if (dst_pg->file.type & VM_MMAP_ADDR) {
          continue;
        }
        struct page *start_addr_pg =
            spt_find_page(dst, dst_pg->file.start_addr);
        enum vm_type pg_type = VM_TYPE(start_addr_pg->operations->type);

        if (pg_type == VM_FILE) {
          dst_pg->file.file = start_addr_pg->file.file;
        } else if (pg_type == VM_UNINIT) {
          struct lazy_load_args *args =
              (struct lazy_load_args *)start_addr_pg->uninit.aux;
          dst_pg->file.file = args->file;
        }
      }
    }
  }
  result = true;

  return result;
}

void supplemental_page_table_hash_destructor(struct hash_elem *e,
                                             void *aux UNUSED) {
  struct page *pg = hash_entry(e, struct page, hash_elem);
  vm_remove_page(pg);
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt) {
  /* TODO: Destroy all the supplemental_page_table hold by thread and
   * TODO: writeback all the modified contents to the storage. */
  if (hash_empty(&spt->table)) {
    return;
  }

  while (true) {
    void *mmap_start_va = NULL;

    struct hash_iterator i;
    hash_first(&i, &spt->table);
    while (hash_next(&i)) {
      struct page *pg = hash_entry(hash_cur(&i), struct page, hash_elem);
      enum vm_type pg_type = VM_TYPE(pg->operations->type);

      bool check_mmap_file_page = pg_type == VM_FILE;
      bool check_mmap_uninit_page =
          pg_type == VM_UNINIT && VM_TYPE(pg->uninit.type) == VM_FILE;

      if (check_mmap_file_page && (pg->file.type & VM_MMAP_ADDR)) {
        ASSERT(pg->va == pg->file.start_addr);
        mmap_start_va = pg->va;
      } else if (check_mmap_uninit_page && (pg->uninit.type & VM_MMAP_ADDR)) {
        mmap_start_va = pg->va;
      }
    }

    if (mmap_start_va != NULL) {
      do_munmap(mmap_start_va);
      mmap_start_va = NULL;
    } else {
      break;
    }
  }

  hash_destroy(&spt->table, &supplemental_page_table_hash_destructor);
}

bool pin_page(void *addr) {
  struct supplemental_page_table *spt = &thread_current()->spt;
  struct page *pg = spt_find_page(spt, addr);
  if (pg == NULL) {
    return false;
  }

  pg->do_not_swap_out = true;
  return true;
}

bool unpin_page(void *addr) {
  struct supplemental_page_table *spt = &thread_current()->spt;
  struct page *pg = spt_find_page(spt, addr);
  if (pg == NULL) {
    return false;
  }

  pg->do_not_swap_out = false;
  return true;
}
