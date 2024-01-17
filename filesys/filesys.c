#include "filesys/filesys.h"

#include <debug.h>
#include <stdio.h>
#include <string.h>

#include "devices/disk.h"
#include "filesys/directory.h"
#include "filesys/fat.h"
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format(void);

struct dir *get_start_directory(const char *path, struct dir *cur_dir);

/* Initializes the file system module.
 * If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
  filesys_disk = disk_get(0, 1);
  if (filesys_disk == NULL)
    PANIC("hd0:1 (hdb) not present, file system initialization failed");

  inode_init();

#ifdef EFILESYS
  fat_init();

  if (format) do_format();

  fat_open();
  thread_current()->cur_dir = dir_open_root();
#else
  /* Original FS */
  free_map_init();

  if (format) do_format();

  free_map_open();
#endif
}

/* Shuts down the file system module, writing any unwritten data
 * to disk. */
void filesys_done(void) {
  /* Original FS */
#ifdef EFILESYS
  fat_close();
#else
  free_map_close();
#endif
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */
bool filesys_create(const char *name, off_t initial_size) {
  disk_sector_t inode_sector = 0;
#ifdef EFILESYS
  struct dir *dir = NULL;

  char *filename = get_filename(name);
  if (filename == NULL) {
    return false;
  }

  bool success = true;
  if (!open_parent_dir(name, thread_current()->cur_dir, &dir)) {
    return false;
  }
  inode_sector = fat_create_chain(0);
  success = (dir != NULL && inode_sector != 0 &&
             inode_create(inode_sector, initial_size, (file_type_t)0) &&
             dir_add(dir, filename, inode_sector));
  if (!success && inode_sector != 0) fat_remove_chain(inode_sector, 0);
#else
  struct dir *dir = dir_open_root();
  bool success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
                  inode_create(inode_sector, initial_size, (file_type_t)0) &&
                  dir_add(dir, name, inode_sector));
  if (!success && inode_sector != 0) free_map_release(inode_sector, 1);
#endif
  dir_close(dir);

  return success;
}

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
struct file *filesys_open(const char *name) {
#ifdef EFILESYS
  struct dir *dir = NULL;
  struct dir *start_dir = thread_current()->cur_dir;
  struct inode *inode = NULL;
  char *path = (char *)calloc(sizeof(char), NAME_MAX + 1);
  strlcpy(path, name, strlen(name) + 1);
  char *filename = NULL;

  while (true) {
    filename = get_filename(path);
    if (filename == NULL) {
      free(path);
      return NULL;
    }
    if (!open_parent_dir(path, start_dir, &dir)) {
      free(path);
      return NULL;
    }

    if (dir != NULL && dir_lookup(dir, filename, &inode)) {
      dir_close(dir);

      // case for soft link
      if (inode_file_type(inode) == (file_type_t)2) {
        struct symlink *link = symlink_open(inode);
        inode_close(inode);

        char *new_path = symlink_path(link);
        strlcpy(path, new_path, strlen(new_path) + 1);
        start_dir = dir_reopen(symlink_start_dir(link));
        symlink_close(link);

        continue;
      }

      break;
    } else {
      free(path);
      return NULL;
    }
  }
  free(path);
#else
  struct dir *dir = dir_open_root();
  struct inode *inode = NULL;

  if (dir != NULL) dir_lookup(dir, name, &inode);
  dir_close(dir);
#endif

  return file_open(inode);
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool filesys_remove(const char *name) {
#ifdef EFILESYS
  char *filename = get_filename(name);
  if (filename == NULL) {
    return false;
  }

  struct dir *dir = NULL;
  if (!open_parent_dir(name, thread_current()->cur_dir, &dir)) {
    return false;
  }
  bool success = false;
  struct inode *inode = NULL;
  if (dir != NULL && dir_lookup(dir, filename, &inode)) {
    if (inode_file_type(inode) != (file_type_t)1) {  // case for not directory
      success = dir_remove(dir, filename);
    } else {  // case for directory
      struct dir *victim = dir_open(inode);
      if (dir_is_empty(victim) &&
          !dir_is_same(thread_current()->cur_dir, victim)) {
        success = dir_remove(dir, filename);
      }
      dir_close(victim);
    }
    inode_close(inode);
  }
  dir_close(dir);

  return success;
#else
  struct dir *dir = dir_open_root();
  bool success = dir != NULL && dir_remove(dir, name);
  dir_close(dir);

  return success;
#endif
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");

#ifdef EFILESYS
  /* Create FAT and save it to the disk. */
  fat_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16)) PANIC("root directory creation failed");
  struct dir *root_dir = dir_open_root();
  if (!dir_add(root_dir, ".", ROOT_DIR_SECTOR) ||
      !dir_add(root_dir, "..", ROOT_DIR_SECTOR)) {
    PANIC("root directory's relative directory creation failed");
  }
  dir_close(root_dir);
  fat_close();
#else
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16)) PANIC("root directory creation failed");
  free_map_close();
#endif

  printf("done.\n");
}

bool filesys_change_dir(const char *name) {
  if (name == NULL || strlen(name) == 0) {
    return false;
  }

  char *last_dirname = get_filename(name);
  if (last_dirname == NULL) {
    return false;
  }

  struct dir *cur_dir = thread_current()->cur_dir;
  struct dir *dir = NULL;
  struct inode *inode = NULL;
  if (open_parent_dir(name, cur_dir, &dir) && dir != NULL &&
      dir_lookup(dir, last_dirname, &inode)) {
    dir_close(dir);
    dir = dir_open(inode);
    if (cur_dir != NULL) {
      dir_close(cur_dir);
    }
    thread_current()->cur_dir = dir;
    return true;
  }
  return false;
}

bool filesys_create_dir(const char *name) {
  bool success = false;
  disk_sector_t inode_sector = 0;
  struct dir *parent_dir = NULL;

  char *new_dirname = get_filename(name);
  if (new_dirname == NULL) {
    return false;
  }

  struct inode *inode = NULL;
  if (!open_parent_dir(name, thread_current()->cur_dir, &parent_dir)) {
    return false;
  }
  if (parent_dir == NULL) {
    return false;
  }
  if (dir_lookup(parent_dir, new_dirname, &inode) == true) {
    return false;
  }

  inode_sector = fat_create_chain(0);

  success = dir_create(inode_sector, DIR_ENTRY_MAX) &&
            dir_add(parent_dir, new_dirname, inode_sector) &&
            dir_lookup(parent_dir, new_dirname, &inode);

  if (!success && inode_sector != 0) {
    fat_remove_chain(inode_sector, 0);
  } else {
    struct dir *new_dir = dir_open(inode);
    success &=
        dir_add(new_dir, ".", inode_sector) &&
        dir_add(new_dir, "..", inode_get_inumber(dir_get_inode(parent_dir)));
    dir_close(new_dir);
  }

  dir_close(parent_dir);

  return success;
}

struct dir *get_start_directory(const char *path, struct dir *cur_dir) {
  if (path[0] == '/') {
    return dir_open_root();
  }
  return dir_reopen(cur_dir);
}

char *get_filename(const char *path) {
  if (path == NULL || strlen(path) == 0) {
    return NULL;
  }

  char *filename = strrchr(path, '/');
  if (filename == NULL) {
    return (char *)path;
  }
  return filename + 1;  // for "/"
}

bool open_parent_dir(const char *path, struct dir *cur_dir,
                     struct dir **parent_dir) {
  if (path == NULL || strlen(path) == 0) {
    return false;
  }

  struct dir *dir = get_start_directory(path, cur_dir);
  if (dir == NULL) {
    return false;
  }

  char *last = strrchr(path, '/');
  size_t parent_path_strlen = last == NULL ? 0 : strlen(path) - strlen(last);

  char *cp_parent_path = (char *)calloc(sizeof(char), parent_path_strlen + 1);
  strlcpy(cp_parent_path, path, parent_path_strlen + 1);
  cp_parent_path[parent_path_strlen] = '\0';

  struct inode *inode = NULL;
  char *token, *save_ptr;

  bool success = false;

  while (true) {
    for (token = strtok_r(cp_parent_path, "/", &save_ptr); token != NULL;
         token = strtok_r(NULL, "/", &save_ptr)) {
      if (!dir_lookup(dir, token, &inode)) {
        dir_close(dir);
        success = false;
        goto done;
      }

      dir_close(dir);
      // not directory
      if (inode_file_type(inode) != (file_type_t)1) {
        inode_close(inode);
        success = false;
        goto done;
      }

      dir = dir_open(inode);
    }

    if (inode && inode_file_type(inode) == (file_type_t)2) {  // symlink
      struct symlink *link = symlink_open(inode);
      inode_close(inode);

      char *new_path = symlink_path(link);

      last = strrchr(new_path, '/');
      size_t new_parent_path_strlen = strlen(new_path) - strlen(last);
      cp_parent_path =
          (char *)realloc(cp_parent_path, new_parent_path_strlen + 1);
      strlcpy(cp_parent_path, new_path, new_parent_path_strlen + 1);
      cp_parent_path[new_parent_path_strlen] = '\0';
      token, save_ptr = NULL;

      dir_close(dir);
      dir = dir_reopen(symlink_start_dir(link));

      symlink_close(link);
      continue;
    }

    inode_close(inode);
    break;
  }
  *parent_dir = dir;
  success = true;

done:
  free(cp_parent_path);
  return success;
}

int filesys_create_symlink(const char *target, const char *linkpath) {
  if (target == NULL || linkpath == NULL || strlen(target) == 0 ||
      strlen(linkpath) == 0) {
    return -1;
  }

  char *symlink_name = get_filename(linkpath);
  if (symlink_name == NULL) {
    return -1;
  }

  bool success = false;
  disk_sector_t inode_sector = 0;
  struct dir *parent_dir = NULL;
  struct inode *inode = NULL;
  struct dir *cur_dir = thread_current()->cur_dir;
  if (open_parent_dir(linkpath, cur_dir, &parent_dir) && parent_dir != NULL &&
      !dir_lookup(parent_dir, symlink_name, &inode)) {
    success = true;
  }

  struct dir *start_dir = get_start_directory(linkpath, cur_dir);
  disk_sector_t start_dir_sector = inode_get_inumber(dir_get_inode(start_dir));
  dir_close(start_dir);

  success &= (free_map_allocate(1, &inode_sector) &&
              symlink_create(inode_sector, target, start_dir_sector) &&
              dir_add(parent_dir, symlink_name, inode_sector) &&
              dir_lookup(parent_dir, symlink_name, &inode));
  dir_close(parent_dir);

  if (success) {
    return 0;
  }
  return -1;
}
