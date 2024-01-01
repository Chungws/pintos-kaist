#include "filesys/filesys.h"

#include <debug.h>
#include <stdio.h>
#include <string.h>

#include "devices/disk.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format(void);

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
  struct dir *dir = NULL;

  char *filename = get_filename(name);
  if (filename == NULL) {
    return false;
  }

  bool success = false;
  if (open_parent_dir(name, thread_current()->cur_dir, &dir)) {
    success = true;
  }
  success = (success && dir != NULL && free_map_allocate(1, &inode_sector) &&
             inode_create(inode_sector, initial_size, (is_dir_t)0) &&
             dir_add(dir, filename, inode_sector));
  if (!success && inode_sector != 0) free_map_release(inode_sector, 1);
  dir_close(dir);

  return success;
}

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
struct file *filesys_open(const char *name) {
  struct dir *dir = dir_open_root();
  struct inode *inode = NULL;

  if (dir != NULL) dir_lookup(dir, name, &inode);
  dir_close(dir);

  return file_open(inode);
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool filesys_remove(const char *name) {
  struct dir *dir = dir_open_root();
  bool success = dir != NULL && dir_remove(dir, name);
  dir_close(dir);

  return success;
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");

#ifdef EFILESYS
  /* Create FAT and save it to the disk. */
  fat_create();
  fat_close();
#else
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16)) PANIC("root directory creation failed");
  free_map_close();
#endif

  printf("done.\n");
}

char *get_filename(const char *path) {
  if (path == NULL || strlen(path) == 0) {
    return NULL;
  }

  char *filename = strrchr(path, "/");
  if (filename == NULL) {
    filename = path;
    return filename;
  }
  return filename + 1;  // for "/"
}

bool open_parent_dir(const char *path, struct dir *cur_dir,
                     struct dir **parent_dir) {
  if (path == NULL || strlen(path) == 0) {
    return false;
  }

  struct dir *dir = NULL;
  if (path[0] == "/") {
    dir = dir_open_root();
  } else if (cur_dir != NULL) {
    dir = dir_reopen(cur_dir);
  } else {
    return false;
  }

  char *last = strrchr(path, "/");
  size_t parent_path_strlen = strlen(path) - strlen(last);

  char *cp_parent_path,
      start = (char *)calloc(sizeof(char), parent_path_strlen + 1);
  strlcpy(cp_parent_path, path, parent_path_strlen + 1);
  cp_parent_path[parent_path_strlen] = "\0";

  struct inode *inode = NULL;
  char *token, *save_ptr;

  bool success = false;

  for (token = strtok_r(cp_parent_path, "/", &save_ptr); token != NULL;
       token = strtok_r(NULL, "/", &save_ptr)) {
    if (!dir_lookup(dir, token, &inode)) {
      dir_close(dir);
      success = false;
      goto done;
    }

    dir_close(dir);
    // normal file, path is wrong
    if (inode_is_dir(inode) == (is_dir_t)0) {
      inode_close(inode);
      success = false;
      goto done;
    }

    dir = dir_open(inode);
  }
  *parent_dir = dir;
  success = true;

done:
  free(start);
  return success;
}
