#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <list.h>
#include <stdbool.h>

#include "devices/disk.h"
#include "filesys/off_t.h"

/* 0 is regular file, 1 is directory, 2 is soft link. */
typedef uint32_t file_type_t;

struct bitmap;

void inode_init(void);
bool inode_create(disk_sector_t, off_t, file_type_t);
struct inode *inode_open(disk_sector_t);
struct inode *inode_reopen(struct inode *);
disk_sector_t inode_get_inumber(const struct inode *);
void inode_close(struct inode *);
void inode_remove(struct inode *);
off_t inode_read_at(struct inode *, void *, off_t size, off_t offset);
off_t inode_write_at(struct inode *, const void *, off_t size, off_t offset);
bool inode_extend(struct inode *inode, int sectors, int new_size);
void inode_deny_write(struct inode *);
void inode_allow_write(struct inode *);
off_t inode_length(const struct inode *);
file_type_t inode_file_type(struct inode *);
off_t inode_get_file_pos(const struct inode *inode);
void inode_file_pos_set(struct inode *inode, off_t pos);
bool inode_removed(struct inode *inode);

#endif /* filesys/inode.h */
