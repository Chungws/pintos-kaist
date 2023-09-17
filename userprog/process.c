#include "userprog/process.h"

#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/mmu.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/gdt.h"
#include "userprog/tss.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup(void);
static bool load(const char *cmd_line, struct intr_frame *if_);
static void initd(void *f_name);
static void __do_fork(void *);
struct process_desc *find_child_desc(tid_t tid);

static struct lock filesys_lock;

struct initd_args {
  char *file_name;
  struct proc_desc *pd;
};

struct fork_args {
  struct thread *parent;
  struct proc_desc *pd;
};

/* General process initializer for initd and other process. */
static void process_init(void) {
  struct thread *current = thread_current();
  lock_init(&filesys_lock);
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t process_create_initd(const char *cmd_line) {
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
   * Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL) return TID_ERROR;
  strlcpy(fn_copy, cmd_line, PGSIZE);

  /* Project 2 : argument passing */
  /* Parse first token of arguments for file name. */
  char *file_name, *save_ptr;
  file_name = strtok_r(cmd_line, " ", &save_ptr);

  struct process_desc *pd;
  pd = palloc_get_page(0);
  if (pd == NULL) return TID_ERROR;
  sema_init(&pd->wait_sema, 0);
  sema_init(&pd->fork_sema, 0);
  for (int i = 0; i < 128; i++) {
    pd->file_desc[i] = NULL;
  }
  pd->exit_status = -1;
  pd->is_terminated = false;

  struct initd_args args;
  args.file_name = fn_copy;
  args.pd = pd;

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(file_name, PRI_DEFAULT, initd, &args);
  sema_down(&pd->fork_sema);

  /* Project 2 : argument passing */
  if (tid == TID_ERROR) {
    palloc_free_page(fn_copy);
    palloc_free_page(pd);
  } else {
    struct thread *cur = thread_current();
    struct thread *t = thread_find_tid(tid);
    if (t == NULL) {
      palloc_free_page(fn_copy);
      palloc_free_page(pd);
      return TID_ERROR;
    }
    pd->pid = tid;
    list_push_back(&cur->child_list, &pd->child_elem);
  }

  return tid;
}

/* A thread function that launches first user process. */
static void initd(void *_initd_args) {
#ifdef VM
  supplemental_page_table_init(&thread_current()->spt);
#endif

  struct initd_args *args = (struct initd_args *)_initd_args;
  struct proc_desc *pd = args->pd;
  struct thread *curr = thread_current();

  process_init();
  curr->proc_desc = pd;
  sema_up(&curr->proc_desc->fork_sema);

  if (process_exec(args->file_name) < 0) PANIC("Fail to launch initd\n");
  NOT_REACHED();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t process_fork(const char *name, struct intr_frame *if_) {
  struct thread *cur = thread_current();
  memcpy(&cur->proc_desc->parent_tf, if_, sizeof(struct intr_frame));

  struct process_desc *pd;
  pd = palloc_get_page(0);
  if (pd == NULL) return TID_ERROR;
  sema_init(&pd->wait_sema, 0);
  sema_init(&pd->fork_sema, 0);
  for (int i = 0; i < 128; i++) {
    pd->file_desc[i] = NULL;
  }

  struct fork_args args = {thread_current(), pd};

  /* Clone current thread to new thread.*/
  tid_t tid = thread_create(name, PRI_DEFAULT, __do_fork, &args);
  if (tid == TID_ERROR) {
    palloc_free_page(pd);
    return tid;
  }
  sema_down(&pd->fork_sema);
  list_push_back(&cur->child_list, &pd->child_elem);

  return tid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool duplicate_pte(uint64_t *pte, void *va, void *aux) {
  struct thread *current = thread_current();
  struct thread *parent = (struct thread *)aux;
  void *parent_page;
  void *newpage;
  bool writable;

  /* 1. TODO: If the parent_page is kernel page, then return immediately. */
  if (is_kernel_vaddr(va)) return true;

  /* 2. Resolve VA from the parent's page map level 4. */
  parent_page = pml4_get_page(parent->pml4, va);
  if (parent_page == NULL) {
    printf("parent page not exist\n");
    return false;
  }

  /* 3. TODO: Allocate new PAL_USER page for the child and set result to
   *    TODO: NEWPAGE. */
  newpage = palloc_get_page(PAL_USER);
  if (newpage == NULL) {
    printf("new page allocation failed\n");
    return false;
  }

  /* 4. TODO: Duplicate parent's page to the new page and
   *    TODO: check whether parent's page is writable or not (set WRITABLE
   *    TODO: according to the result). */
  memcpy(newpage, parent_page, PGSIZE);
  writable = is_writable(pte);

  /* 5. Add new page to child's page table at address VA with WRITABLE
   *    permission. */
  if (!pml4_set_page(current->pml4, va, newpage, writable)) {
    /* 6. TODO: if fail to insert page, do error handling. */
    printf("new page is not addition failed\n");
    return false;
  }
  return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void __do_fork(void *aux) {
  struct intr_frame if_;
  struct fork_args *f_args = (struct fork_args *)aux;
  struct thread *parent = f_args->parent;
  struct process_desc *pd = f_args->pd;
  struct thread *current = thread_current();
  /* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
  struct intr_frame *parent_if = &parent->proc_desc->parent_tf;
  bool succ = true;

  /* 1. Read the cpu context to local stack. */
  memcpy(&if_, parent_if, sizeof(struct intr_frame));

  /* 2. Duplicate PT */
  current->pml4 = pml4_create();
  if (current->pml4 == NULL) goto error;

  process_activate(current);
#ifdef VM
  supplemental_page_table_init(&current->spt);
  if (!supplemental_page_table_copy(&current->spt, &parent->spt)) goto error;
#else
  if (!pml4_for_each(parent->pml4, duplicate_pte, parent)) goto error;
#endif

  /* TODO: Your code goes here.
   * TODO: Hint) To duplicate the file object, use `file_duplicate`
   * TODO:       in include/filesys/file.h. Note that parent should not return
   * TODO:       from the fork() until this function successfully duplicates
   * TODO:       the resources of parent.*/

  if_.R.rax = 0;

  pd->exit_status = parent->proc_desc->exit_status;
  pd->is_terminated = parent->proc_desc->is_terminated;
  pd->pid = current->tid;

  lock_acquire(&filesys_lock);
  current->running_file = file_duplicate(parent->running_file);
  for (int i = 2; i < 128; i++) {
    struct file *f = parent->proc_desc->file_desc[i];
    if (f != NULL) {
      pd->file_desc[i] = file_duplicate(f);
    }
  }
  lock_release(&filesys_lock);

  current->proc_desc = pd;

  sema_up(&current->proc_desc->fork_sema);
  /* Finally, switch to the newly created process. */
  if (succ) {
    do_iret(&if_);
  }
error:
  current->proc_desc = pd;
  current->proc_desc->exit_status = -1;
  sema_up(&pd->fork_sema);
  thread_exit();
}

/* Project 2 : argument passing */
void argument_stack(int argc, char **argv, struct intr_frame *_if) {
  for (int i = argc - 1; i >= 0; i--) {
    int arg_len = strlen(argv[i]) + 1;
    _if->rsp -= arg_len;
    memset((void *)_if->rsp, 0, arg_len);
    memcpy((void *)_if->rsp, argv[i], arg_len);
    argv[i] = (char *)_if->rsp;
  }

  // 8 byte word align
  if (_if->rsp % 8 != 0) {
    int word_align = _if->rsp % 8;
    _if->rsp -= word_align;
    memset((void *)_if->rsp, 0, word_align);
  }

  // for argv[argc]
  _if->rsp -= 8;
  memset((void *)_if->rsp, 0, 8);

  for (int i = argc - 1; i >= 0; i--) {
    _if->rsp -= 8;
    memcpy((void *)_if->rsp, &argv[i], 8);
  }

  // for fake return address
  _if->rsp -= 8;
  memset((void *)_if->rsp, 0, 8);

  _if->R.rdi = (uint64_t)argc;
  _if->R.rsi = (uint64_t)_if->rsp + 8;
}
/* Project 2 : argument passing */

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int process_exec(void *f_name) {
  char *file_name = (char *)palloc_get_page(0);
  if (file_name == NULL) return -1;
  strlcpy(file_name, f_name, PGSIZE);
  bool success;

  /* We cannot use the intr_frame in the thread structure.
   * This is because when current thread rescheduled,
   * it stores the execution information to the member. */
  struct intr_frame _if;
  _if.ds = _if.es = _if.ss = SEL_UDSEG;
  _if.cs = SEL_UCSEG;
  _if.eflags = FLAG_IF | FLAG_MBS;

  /* We first kill the current context */
  process_cleanup();

  struct thread *curr = thread_current();

  // if (filesys_lock.holder == curr) {
  //   lock_release(&filesys_lock);
  // }

  if (curr->running_file != NULL) {
    lock_acquire(&filesys_lock);
    file_allow_write(curr->running_file);
    file_close(curr->running_file);
    curr->running_file = NULL;
    lock_release(&filesys_lock);
  }

  /* Project 2 : argument passing */

  /* And then load the binary */
  success = load(file_name, &_if);

  // hex_dump(_if.rsp, (void *)_if.rsp, USER_STACK - (uint64_t)_if.rsp, true);
  /* Project 2 : argument passing */

  /* If load failed, quit. */
  palloc_free_page(file_name);
  if (!success) return -1;

  /* Start switched process. */
  do_iret(&_if);
  NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int process_wait(tid_t child_tid) {
  /* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
   * XXX:       to add infinite loop here before
   * XXX:       implementing the process_wait. */
  /* Project 2 : argument passing */
  struct thread *curr = thread_current();

  struct process_desc *child_desc = find_child_desc(child_tid);
  if (child_desc == NULL) {
    return -1;
  }

  list_remove(&child_desc->child_elem);

  if (!child_desc->is_terminated) {
    sema_down(&child_desc->wait_sema);
  }

  int child_exit_status = child_desc->exit_status;
  palloc_free_page(child_desc);
  /* Project 2 : argument passing */
  return child_exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
void process_exit(void) {
  struct thread *curr = thread_current();
  /* TODO: Your code goes here.
   * TODO: Implement process termination message (see
   * TODO: project2/process_termination.html).
   * TODO: We recommend you to implement process resource cleanup here. */
  if (filesys_lock.holder == curr) {
    lock_release(&filesys_lock);
  }

  if (curr->running_file != NULL) {
    lock_acquire(&filesys_lock);
    file_allow_write(curr->running_file);
    file_close(curr->running_file);
    curr->running_file = NULL;
    lock_release(&filesys_lock);
  }

  struct process_desc *proc_desc = curr->proc_desc;
  if (proc_desc != NULL) {
    lock_acquire(&filesys_lock);
    for (int i = 2; i < 128; i++) {
      struct file *f = proc_desc->file_desc[i];
      if (f != NULL) {
        file_close(f);
        proc_desc->file_desc[i] = NULL;
      }
    }
    lock_release(&filesys_lock);
    proc_desc->is_terminated = true;

    sema_up(&curr->proc_desc->wait_sema);
    printf("%s: exit(%d)\n", curr->name, curr->proc_desc->exit_status);
  }
  process_cleanup();
}

/* Free the current process's resources. */
static void process_cleanup(void) {
  struct thread *curr = thread_current();

#ifdef VM
  supplemental_page_table_kill(&curr->spt);
#endif

  uint64_t *pml4;
  /* Destroy the current process's page directory and switch back
   * to the kernel-only page directory. */
  pml4 = curr->pml4;
  if (pml4 != NULL) {
    /* Correct ordering here is crucial.  We must set
     * cur->pagedir to NULL before switching page directories,
     * so that a timer interrupt can't switch back to the
     * process page directory.  We must activate the base page
     * directory before destroying the process's page
     * directory, or our active page directory will be one
     * that's been freed (and cleared). */
    curr->pml4 = NULL;
    pml4_activate(NULL);
    pml4_destroy(pml4);
  }
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void process_activate(struct thread *next) {
  /* Activate thread's page tables. */
  pml4_activate(next->pml4);

  /* Set thread's kernel stack for use in processing interrupts. */
  tss_update(next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
  unsigned char e_ident[EI_NIDENT];
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  uint64_t e_entry;
  uint64_t e_phoff;
  uint64_t e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
};

struct ELF64_PHDR {
  uint32_t p_type;
  uint32_t p_flags;
  uint64_t p_offset;
  uint64_t p_vaddr;
  uint64_t p_paddr;
  uint64_t p_filesz;
  uint64_t p_memsz;
  uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack(struct intr_frame *if_);
static bool validate_segment(const struct Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool load(const char *cmd_line, struct intr_frame *if_) {
  struct thread *t = thread_current();
  struct ELF ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  char *token, *save_ptr;
  char *argv[64];
  int argc = 0;

  for (token = strtok_r(cmd_line, " ", &save_ptr); token != NULL;
       token = strtok_r(NULL, " ", &save_ptr)) {
    argv[argc] = token;
    argc++;
  }

  lock_acquire(&filesys_lock);
  /* Allocate and activate page directory. */
  t->pml4 = pml4_create();
  if (t->pml4 == NULL) goto done;
  process_activate(thread_current());

  /* Open executable file. */
  file = filesys_open(argv[0]);
  if (file == NULL) {
    printf("load: %s: open failed\n", argv[0]);
    goto done;
  }

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\2\1\1", 7) || ehdr.e_type != 2 ||
      ehdr.e_machine != 0x3E  // amd64
      || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Phdr) ||
      ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", argv[0]);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file)) goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr) goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint64_t file_page = phdr.p_offset & ~PGMASK;
          uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint64_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
             * Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes =
                (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
             * Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void *)mem_page, read_bytes,
                            zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(if_)) goto done;

  /* Start address. */
  if_->rip = ehdr.e_entry;

  /* TODO: Your code goes here.
   * TODO: Implement argument passing (see project2/argument_passing.html). */

  file_deny_write(file);
  t->running_file = file;
  success = true;
  lock_release(&filesys_lock);

  /* Set arguments in user stack */
  argument_stack(argc, argv, if_);

  return success;

done:
  /* We arrive here whether the load is successful or not. */
  file_close(file);
  lock_release(&filesys_lock);
  return success;
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Phdr *phdr, struct file *file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (uint64_t)file_length(file)) return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0) return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void *)phdr->p_vaddr)) return false;
  if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz))) return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr) return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE) return false;

  /* It's okay. */
  return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page(void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Do calculate how to fill this page.
     * We will read PAGE_READ_BYTES bytes from FILE
     * and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t *kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL) return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      printf("fail\n");
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool setup_stack(struct intr_frame *if_) {
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t *)USER_STACK) - PGSIZE, kpage, true);
    if (success)
      if_->rsp = USER_STACK;
    else
      palloc_free_page(kpage);
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool install_page(void *upage, void *kpage, bool writable) {
  struct thread *t = thread_current();

  /* Verify that there's not already a page at that virtual
   * address, then map our page there. */
  return (pml4_get_page(t->pml4, upage) == NULL &&
          pml4_set_page(t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool lazy_load_segment(struct page *page, void *aux) {
  /* TODO: Load the segment from the file */
  /* TODO: This called when the first page fault occurs on address VA. */
  /* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  while (read_bytes > 0 || zero_bytes > 0) {
    /* Do calculate how to fill this page.
     * We will read PAGE_READ_BYTES bytes from FILE
     * and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* TODO: Set up aux to pass information to the lazy_load_segment. */
    void *aux = NULL;
    if (!vm_alloc_page_with_initializer(VM_ANON, upage, writable,
                                        lazy_load_segment, aux))
      return false;

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool setup_stack(struct intr_frame *if_) {
  bool success = false;
  void *stack_bottom = (void *)(((uint8_t *)USER_STACK) - PGSIZE);

  /* TODO: Map the stack on stack_bottom and claim the page immediately.
   * TODO: If success, set the rsp accordingly.
   * TODO: You should mark the page is stack. */
  /* TODO: Your code goes here */

  return success;
}
#endif /* VM */

struct process_desc *find_child_desc(tid_t tid) {
  struct thread *curr = thread_current();

  struct process_desc *child_pd = NULL;
  for (struct list_elem *e = list_begin(&curr->child_list);
       e != list_end(&curr->child_list); e = list_next(e)) {
    struct process_desc *pd = list_entry(e, struct process_desc, child_elem);
    if (pd->pid == tid) {
      child_pd = pd;
      break;
    }
  }
  return child_pd;
}

void filesys_lock_acquire() { lock_acquire(&filesys_lock); }
void filesys_lock_release() { lock_release(&filesys_lock); }
