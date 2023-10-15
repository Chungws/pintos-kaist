#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "devices/input.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/thread.h"
#include "userprog/gdt.h"
#include "userprog/process.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

void sys_halt(void);
void sys_exit(int status);
pid_t sys_fork(const char *thread_name, struct intr_frame *_if);
int sys_exec(const char *cmd_line);
int sys_wait(pid_t pid);
bool sys_create(const char *file, unsigned initial_size);
bool sys_remove(const char *file);
int sys_open(const char *file);
int sys_filesize(int fd);
int sys_read(int fd, void *buffer, unsigned size);
int sys_write(int fd, const void *buffer, unsigned size);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
void sys_close(int fd);
void validate_address(uint64_t addr);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void) {
  write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG)
                                                               << 32);
  write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

  /* The interrupt service rountine should not serve any interrupts
   * until the syscall_entry swaps the userland stack to the kernel
   * mode stack. Therefore, we masked the FLAG_FL. */
  write_msr(MSR_SYSCALL_MASK,
            FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f) {
  // TODO: Your implementation goes here.

  int syscall_number = f->R.rax;
  // printf("system call! : %d\n", syscall_number);
  uint64_t arg1 = f->R.rdi;
  uint64_t arg2 = f->R.rsi;
  uint64_t arg3 = f->R.rdx;
  uint64_t arg4 = f->R.r10;
  uint64_t arg5 = f->R.r8;
  uint64_t arg6 = f->R.r9;

  switch (syscall_number) {
    case SYS_HALT:
      sys_halt();
      break;
    case SYS_EXIT:
      sys_exit((int)arg1);
      break;
    case SYS_FORK:
      f->R.rax = (uint64_t)(sys_fork((const char *)arg1, f));
      break;
    case SYS_EXEC:
      f->R.rax = (uint64_t)(sys_exec((const char *)arg1));
      break;
    case SYS_WAIT:
      f->R.rax = (uint64_t)(sys_wait((pid_t)arg1));
      break;
    case SYS_CREATE:
      f->R.rax = (uint64_t)sys_create((const char *)arg1, (unsigned)arg2);
      break;
    case SYS_REMOVE:
      f->R.rax = (uint64_t)sys_remove((const char *)arg1);
      break;
    case SYS_OPEN:
      f->R.rax = (uint64_t)sys_open((const char *)arg1);
      break;
    case SYS_FILESIZE:
      f->R.rax = (uint64_t)sys_filesize((int)arg1);
      break;
    case SYS_READ:
      f->R.rax = (uint64_t)sys_read((int)arg1, (void *)arg2, (unsigned)arg3);
      break;
    case SYS_WRITE:
      f->R.rax =
          (uint64_t)sys_write((int)arg1, (const void *)arg2, (unsigned)arg3);
      break;
    case SYS_SEEK:
      sys_seek((int)arg1, (unsigned)arg2);
      break;
    case SYS_TELL:
      f->R.rax = (uint64_t)sys_tell((int)arg1);
      break;
    case SYS_CLOSE:
      sys_close((int)arg1);
      break;
    case SYS_DUP2:
      // sys_dup2();
      break;
    default:
      printf("Not implemented system call\n");
      break;
  }
  // thread_exit();
}

void sys_halt(void) { power_off(); }

void sys_exit(int status) {
  struct thread *cur = thread_current();
  cur->proc_desc->exit_status = status;
  thread_exit();
}

pid_t sys_fork(const char *thread_name, struct intr_frame *_if) {
  validate_address((uint64_t)thread_name);
  return process_fork(thread_name, _if);
}

int sys_exec(const char *cmd_line) {
  validate_address((uint64_t)cmd_line);
  if (process_exec((void *)cmd_line) == -1) {
    sys_exit(-1);
  }
  NOT_REACHED();
}

int sys_wait(pid_t pid) { return process_wait((tid_t)pid); }

bool sys_create(const char *file, unsigned initial_size) {
  validate_address((uint64_t)file);
  filesys_lock_acquire();
  bool result = filesys_create(file, initial_size);
  filesys_lock_release();
  return result;
}

bool sys_remove(const char *file) {
  validate_address((uint64_t)file);
  filesys_lock_acquire();
  bool result = filesys_remove(file);
  filesys_lock_release();
  return result;
}

int sys_open(const char *file) {
  validate_address((uint64_t)file);
  filesys_lock_acquire();
  struct file *f = filesys_open(file);
  if (f == NULL) {
    filesys_lock_release();
    return -1;
  }

  struct thread *cur = thread_current();
  for (int i = 2; i < 128; i++) {
    if (cur->proc_desc->file_desc[i] == NULL) {
      cur->proc_desc->file_desc[i] = f;
      filesys_lock_release();
      return i;
    }
  }

  file_close(f);
  filesys_lock_release();
  return -1;
}

int sys_filesize(int fd) {
  if (fd < 2) {
    return 0;
  }

  struct thread *cur = thread_current();

  filesys_lock_acquire();
  struct file *f = cur->proc_desc->file_desc[fd];
  if (f == NULL) {
    filesys_lock_release();
    return 0;
  }
  int result = file_length(f);
  filesys_lock_release();

  return result;
}

int sys_read(int fd, void *buffer, unsigned size) {
  validate_address((uint64_t)buffer);
  if (fd == 0) {
    uint8_t *buf = buffer;
    unsigned result = 0;
    for (unsigned i = 0; i < size; i++) {
      *buf = input_getc();
      buf++;
      result++;
      if ((char)(*buf) == '\0') {
        break;
      }
    }
    return result;
  } else if (fd == 1) {
    return -1;
  } else {
    struct thread *cur = thread_current();

    filesys_lock_acquire();
    struct file *f = cur->proc_desc->file_desc[fd];
    if (f == NULL) {
      filesys_lock_release();
      return -1;
    }
    int result = file_read(f, buffer, size);
    filesys_lock_release();
    return result;
  }
}

int sys_write(int fd, const void *buffer, unsigned size) {
  validate_address((uint64_t)buffer);

  if (fd == 0) {
    return -1;
  } else if (fd == 1) {
    const uint8_t *buf = buffer;
    unsigned result = 0;
    for (unsigned i = 0; i < size; i++) {
      putchar(*buf);
      buf++;
      result++;
      if ((char)(*buf) == '\0') {
        break;
      }
    }
    return result;
  } else {
    struct thread *cur = thread_current();

    filesys_lock_acquire();
    struct file *f = cur->proc_desc->file_desc[fd];
    if (f == NULL) {
      filesys_lock_release();
      return -1;
    }
    int result = file_write(f, buffer, size);
    filesys_lock_release();

    return result;
  }
}

void sys_seek(int fd, unsigned position) {
  if (fd < 2) {
    return;
  }

  struct thread *cur = thread_current();

  filesys_lock_acquire();
  struct file *f = cur->proc_desc->file_desc[fd];
  if (f == NULL) {
    filesys_lock_release();
    return;
  }

  file_seek(f, position);
  filesys_lock_release();
}

unsigned sys_tell(int fd) {
  if (fd < 2) {
    return 0;
  }

  struct thread *cur = thread_current();

  filesys_lock_acquire();
  struct file *f = cur->proc_desc->file_desc[fd];
  if (f == NULL) {
    filesys_lock_release();
    return 0;
  }
  unsigned result = file_tell(f);
  filesys_lock_release();

  return result;
}

void sys_close(int fd) {
  if (fd < 2) {
    return;
  }

  struct thread *cur = thread_current();

  filesys_lock_acquire();
  struct file *f = cur->proc_desc->file_desc[fd];
  if (f == NULL) {
    filesys_lock_release();
    return;
  }

  file_close(f);
  cur->proc_desc->file_desc[fd] = NULL;
  filesys_lock_release();
}

void validate_address(uint64_t addr) {
  if (addr == NULL || !is_user_vaddr(addr)) {
    sys_exit(-1);
  }
}
