#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include <hash.h>
#include <stdio.h>

#include "threads/thread.h"

#define STDIN_FD ((struct file *)1)
#define STDOUT_FD ((struct file *)2)

struct process_desc {
  tid_t pid;
  int exit_status;
  bool is_parent_terminated;
  bool is_terminated;
  struct semaphore wait_sema;
  struct semaphore fork_sema;
  struct intr_frame parent_tf;
  struct hash file_desc_table;
  int next_fd;
  int stdin_count;
  int stdout_count;
  struct list_elem child_elem;
#ifdef VM
  struct hash mmap_table;
#endif /* VM */
};

tid_t process_create_initd(const char *file_name);
tid_t process_fork(const char *name, struct intr_frame *if_);
int process_exec(void *f_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(struct thread *next);
void filesys_lock_acquire(void);
void filesys_lock_release(void);
struct file_desc *file_desc_create(int fd, struct file *f);
void file_desc_destroy(struct file_desc *desc);
bool file_desc_table_insert(struct hash *h, struct file_desc *desc);
struct file *file_desc_table_find_file(struct hash *h, int fd);

bool mmap_table_insert(struct hash *h, uint64_t addr);
bool mmap_table_find_addr(struct hash *h, uint64_t addr);
void mmap_table_delete(struct hash *h, uint64_t addr);

bool lazy_load_segment(struct page *page, void *aux);

#endif /* userprog/process.h */
