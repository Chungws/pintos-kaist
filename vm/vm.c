/* vm.c: Generic interface for virtual memory objects. */

#include "vm/vm.h"

#include <string.h>

#include "threads/malloc.h"
#include "threads/mmu.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "vm/inspect.h"

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
      case VM_ANON | VM_MARKER_0:  // case for stack
        page_initializer = &anon_initializer;
        break;
      case VM_FILE:
        page_initializer = &file_backed_initializer;
        break;
    }

    uninit_new(pg, upage, init, type, aux, page_initializer);
    pg->writable = writable;

    if (!spt_insert_page(spt, pg)) {
      free(pg);
      goto err;
    }

    return true;
    /* TODO: Insert the page into the spt. */
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
  vm_dealloc_page(page);
  return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *vm_get_victim(void) {
  struct frame *victim = NULL;
  /* TODO: The policy for eviction is up to you. */

  return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *vm_evict_frame(void) {
  struct frame *victim UNUSED = vm_get_victim();
  /* TODO: swap out the victim and return the evicted frame. */

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
  } else {
    PANIC("Implement if palloc_get_page failed (swap out)");
  }

  ASSERT(frame != NULL);
  ASSERT(frame->page == NULL);
  return frame;
}

/* Growing the stack. */
static void vm_stack_growth(void *addr UNUSED) {}

/* Handle the fault on write_protected page */
static bool vm_handle_wp(struct page *page UNUSED) {}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool user,
                         bool write, bool not_present) {
  struct supplemental_page_table *spt = &thread_current()->spt;
  // struct hash_iterator i;
  // hash_first(&i, &spt->table);
  // bool result = false;
  // int count = 0;
  // while (hash_next(&i)) {
  //   struct page *pg = hash_entry(hash_cur(&i), struct page, hash_elem);
  //   printf("%d : %p type(%d)\n", count, pg->va, pg->operations->type);
  //   count++;
  // }
  struct page *page = NULL;
  /* TODO: Validate the fault */
  /* TODO: Your code goes here */
  if (addr == NULL || is_kernel_vaddr(addr) || !not_present) {
    return false;
  }

  page = spt_find_page(spt, addr);
  if (page == NULL || (write && !page->writable)) {
    return false;
  }

  return vm_do_claim_page(page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page) {
  destroy(page);
  free(page);
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
  if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva,
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

  aux->file = file_reopen(src_aux->file);
  aux->ofs = src_aux->ofs;
  aux->page_read_bytes = src_aux->page_read_bytes;
  aux->page_zero_bytes = src_aux->page_zero_bytes;

  if (aux->file == NULL) {
    return false;
  }
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

  ASSERT(dst->frame != NULL);
  memcpy(dst->frame->kva, src->frame->kva, PGSIZE);
  return true;
}

bool handle_copy_file_page(struct page *src) {}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst,
                                  struct supplemental_page_table *src) {
  struct hash_iterator i;
  hash_first(&i, &src->table);
  bool result = false;

  while (hash_next(&i)) {
    struct page *src_pg = hash_entry(hash_cur(&i), struct page, hash_elem);
    enum vm_type type = src_pg->operations->type;

    switch (type) {
      case VM_UNINIT:
        if (!handle_copy_uninit_page(src_pg)) {
          return false;
        }
        break;
      case VM_ANON:
      case VM_ANON | VM_MARKER_0:
        if (!handle_copy_anon_page(src_pg)) {
          return false;
        }
        break;
      case VM_FILE:
        // if (!handle_copy_file_page(src_pg)) {
        //   return false;
        // }
        break;
    }
  }
  result = true;

  return result;
}

void supplemental_page_table_hash_destructor(struct hash_elem *e,
                                             void *aux UNUSED) {
  struct page *pg = hash_entry(e, struct page, hash_elem);
  if (pg->operations->type == VM_FILE) {
    do_munmap (pg->va);
  }
  if (pg->frame != NULL) {
    pg->frame->page = NULL;
  }
  vm_dealloc_page(pg);
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt) {
  /* TODO: Destroy all the supplemental_page_table hold by thread and
   * TODO: writeback all the modified contents to the storage. */
  if (hash_empty(&spt->table)) {
    return;
  }
  hash_destroy(&spt->table, &supplemental_page_table_hash_destructor);
}
