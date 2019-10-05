#ifndef _NTFS_LINUX_H
#define _NTFS_LINUX_H

#include <linux/fs.h>
#include "inode.h"

static inline ntfs_inode *EXNTFS_I(struct inode *inode)
{
	return container_of(inode, ntfs_inode, vfs_inode);
}

static inline struct inode *EXNTFS_V(ntfs_inode *ni)
{
	return &ni->vfs_inode;
}

#endif
