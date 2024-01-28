#include "filesys/directory.h"

#include <list.h>
#include <stdio.h>
#include <string.h>

#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"

/* A directory. */
struct dir {
  struct inode *inode; /* Backing store. */
  off_t pos;           /* Current position. */
};

/* A single directory entry. */
struct dir_entry {
  disk_sector_t inode_sector; /* Sector number of header. */
  char name[NAME_MAX + 1];    /* Null terminated file name. */
  bool in_use;                /* In use or free? */
};

struct symlink {
  struct inode *inode;
  char *path;
  struct dir *start_dir;
};

struct symlink_entry {
  disk_sector_t start_dir_sector;
  char path[NAME_MAX + 1];
};

/* Creates a directory with space for ENTRY_CNT entries in the
 * given SECTOR.  Returns true if successful, false on failure. */
bool dir_create(disk_sector_t sector, size_t entry_cnt) {
  return inode_create(sector, entry_cnt * sizeof(struct dir_entry),
                      FILETYPE_DIR);
}

/* Opens and returns the directory for the given INODE, of which
 * it takes ownership.  Returns a null pointer on failure. */
struct dir *dir_open(struct inode *inode) {
  struct dir *dir = calloc(1, sizeof *dir);
  if (inode != NULL && dir != NULL) {
    dir->inode = inode;
    dir->pos = 0;
    return dir;
  } else {
    inode_close(inode);
    free(dir);
    return NULL;
  }
}

/* Opens the root directory and returns a directory for it.
 * Return true if successful, false on failure. */
struct dir *dir_open_root(void) {
  return dir_open(inode_open(ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
 * Returns a null pointer on failure. */
struct dir *dir_reopen(struct dir *dir) {
  return dir_open(inode_reopen(dir->inode));
}

/* Destroys DIR and frees associated resources. */
void dir_close(struct dir *dir) {
  if (dir != NULL) {
    inode_close(dir->inode);
    free(dir);
  }
}

void dir_close_wo_inode(struct dir *dir) {
  if (dir != NULL) {
    free(dir);
  }
}

/* Returns the inode encapsulated by DIR. */
struct inode *dir_get_inode(struct dir *dir) { return dir->inode; }

/* Searches DIR for a file with the given NAME.
 * If successful, returns true, sets *EP to the directory entry
 * if EP is non-null, and sets *OFSP to the byte offset of the
 * directory entry if OFSP is non-null.
 * otherwise, returns false and ignores EP and OFSP. */
static bool lookup(const struct dir *dir, const char *name,
                   struct dir_entry *ep, off_t *ofsp) {
  struct dir_entry e;
  size_t ofs;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  if (inode_removed(dir->inode)) {
    return false;
  }

  for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
    if (e.in_use && !strcmp(name, e.name)) {
      if (ep != NULL) *ep = e;
      if (ofsp != NULL) *ofsp = ofs;
      return true;
    }
  return false;
}

/* Searches DIR for a file with the given NAME
 * and returns true if one exists, false otherwise.
 * On success, sets *INODE to an inode for the file, otherwise to
 * a null pointer.  The caller must close *INODE. */
bool dir_lookup(const struct dir *dir, const char *name, struct inode **inode) {
  struct dir_entry e;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  if (lookup(dir, name, &e, NULL))
    *inode = inode_open(e.inode_sector);
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
 * file by that name.  The file's inode is in sector
 * INODE_SECTOR.
 * Returns true if successful, false on failure.
 * Fails if NAME is invalid (i.e. too long) or a disk or memory
 * error occurs. */
bool dir_add(struct dir *dir, const char *name, disk_sector_t inode_sector) {
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen(name) > NAME_MAX) return false;

  if (inode_removed(dir->inode)) {
    goto done;
  }

  /* Check that NAME is not in use. */
  if (lookup(dir, name, NULL, NULL)) goto done;

  /* Set OFS to offset of free slot.
   * If there are no free slots, then it will be set to the
   * current end-of-file.

   * inode_read_at() will only return a short read at end of file.
   * Otherwise, we'd need to verify that we didn't get a short
   * read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
    if (!e.in_use) break;

  /* Write slot. */
  e.in_use = true;
  strlcpy(e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at(dir->inode, &e, sizeof e, ofs) == sizeof e;

done:
  return success;
}

/* Removes any entry for NAME in DIR.
 * Returns true if successful, false on failure,
 * which occurs only if there is no file with the given NAME. */
bool dir_remove(struct dir *dir, const char *name) {
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  /* Find directory entry. */
  if (!lookup(dir, name, &e, &ofs)) goto done;

  /* Open inode. */
  inode = inode_open(e.inode_sector);
  if (inode == NULL) goto done;

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at(dir->inode, &e, sizeof e, ofs) != sizeof e) goto done;

  /* Remove inode. */
  inode_remove(inode);
  success = true;

done:
  inode_close(inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
 * NAME.  Returns true if successful, false if the directory
 * contains no more entries. */
bool dir_readdir(struct dir *dir, char name[NAME_MAX + 1]) {
  struct dir_entry e;
  dir->pos = inode_file_pos(dir->inode);
  while (inode_read_at(dir->inode, &e, sizeof e, dir->pos) == sizeof e) {
    dir->pos += sizeof e;
    inode_file_pos_set(dir->inode, dir->pos);
    if (e.in_use) {
      strlcpy(name, e.name, NAME_MAX + 1);
      return true;
    }
  }
  return false;
}

bool dir_is_empty(struct dir *dir) {
  char *tmp = (char *)malloc(NAME_MAX + 1);
  struct dir *tmp_dir = dir_reopen(dir);
  dir_readdir(tmp_dir, tmp);  // case for "."
  dir_readdir(tmp_dir, tmp);  // case for ".."

  bool success = false;
  if (!dir_readdir(tmp_dir, tmp)) {
    success = true;
  }
  free(tmp);
  dir_close(tmp_dir);
  return success;
}

bool dir_is_same(struct dir *dir1, struct dir *dir2) {
  return inode_get_inumber(dir1->inode) == inode_get_inumber(dir2->inode);
}

bool symlink_create(disk_sector_t sector, const char *path,
                    disk_sector_t start_dir_sector) {
  struct symlink_entry e;
  bool success = false;
  if (inode_create(sector, sizeof(struct symlink_entry), FILETYPE_SYMLINK)) {
    struct inode *inode = inode_open(sector);
    strlcpy(e.path, path, sizeof(e.path));
    e.start_dir_sector = start_dir_sector;
    if (inode_write_at(inode, &e, sizeof e, 0) == sizeof e) {
      success = true;
    }
    inode_close(inode);
  }
  return success;
}

struct symlink *symlink_open(struct inode *inode) {
  struct symlink *symlink = calloc(1, sizeof *symlink);
  if (inode != NULL && symlink != NULL) {
    symlink->inode = inode;
    struct symlink_entry e;
    inode_read_at(inode, &e, sizeof e, 0);
    symlink->path = calloc(1, sizeof(e.path));
    strlcpy(symlink->path, e.path, sizeof(e.path));
    symlink->start_dir = dir_open(inode_open(e.start_dir_sector));
    return symlink;
  } else {
    inode_close(inode);
    free(symlink);
    return NULL;
  }
}

void symlink_close(struct symlink *link) {
  if (link != NULL) {
    inode_close(link->inode);
    free(link->path);
    dir_close(link->start_dir);
    free(link);
  }
}

char *symlink_path(struct symlink *link) { return link->path; }

struct dir *symlink_start_dir(struct symlink *link) { return link->start_dir; }
