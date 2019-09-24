#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/parser.h>
#include <linux/random.h>
#include <linux/buffer_head.h>
#include <linux/exportfs.h>
#include <linux/vfs.h>
#include <linux/seq_file.h>
#include <linux/mount.h>
#include <linux/log2.h>
#include <linux/quotaops.h>
#include <linux/uaccess.h>
#include <linux/dax.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,20,0)
#include <linux/iversion.h>
#endif

#include "super.h"

#include "logging.h"
#include "layout.h"
#include "bootsect.h"
#include "dir.h"
#include "misc.h"

static struct inode *ntfs_iget(struct super_block *sb, unsigned long ino);

static struct inode *ntfs_alloc_inode(struct super_block *sb)
{
	ntfs_log_debug("%s\n", __func__);
	ntfs_inode *ni;
	ni = ntfs_inode_allocate(sb->s_fs_info);
	if (!ni)
		return NULL;

	inode_set_iversion(&ni->vfs_inode, 1);
	inode_init_once(&ni->vfs_inode);
	return &ni->vfs_inode;
}

static void ntfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	ntfs_inode *ni = EXNTFS_I(inode);
	ntfs_inode_release(ni);
}

static void ntfs_destroy_inode(struct inode *inode)
{
	ntfs_log_debug("%s\n", __func__);
	call_rcu(&inode->i_rcu, ntfs_i_callback);
}

static int ntfs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	ntfs_log_debug("%s\n", __func__);
	return 0;
}

static void ntfs_evict_inode(struct inode *inode)
{
	ntfs_log_debug("%s\n", __func__);
	truncate_inode_pages(&inode->i_data, 0);

	if (!inode->i_nlink)
		i_size_write(inode, 0);
	invalidate_inode_buffers(inode);
	clear_inode(inode);

//	remove_inode_hash(inode);
}

static void ntfs_put_super(struct super_block *sb)
{
	ntfs_log_debug("%s\n", __func__);
}

static int ntfs_sync_fs(struct super_block *sb, int wait)
{
	ntfs_log_debug("%s\n", __func__);
	int err = 0;


	return err;
}

static int ntfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	ntfs_log_debug("%s\n", __func__);
	return -1;
}

static int ntfs_remount(struct super_block *sb, int *flags, char *data)
{
	ntfs_log_debug("%s\n", __func__);
	return -1;
}

static int ntfs_show_options(struct seq_file *m, struct dentry *root)
{
	ntfs_log_debug("%s\n", __func__);
	return 0;
}

static const struct super_operations ntfs_sops = {
	.alloc_inode	= ntfs_alloc_inode,
	.destroy_inode	= ntfs_destroy_inode,
	.write_inode	= ntfs_write_inode,
	.evict_inode	= ntfs_evict_inode,
	.put_super	= ntfs_put_super,
	.sync_fs	= ntfs_sync_fs,
	.statfs		= ntfs_statfs,
	.remount_fs	= ntfs_remount,
	.show_options	= ntfs_show_options,
};

static int __ntfs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
						bool excl)
{
	ntfs_log_debug("%s\n", __func__);
	return -EOPNOTSUPP;
}


#if 0
static int ntfs_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, minix_get_block, wbc);
}

static int ntfs_readpage(struct file *file, struct page *page)
{
	return block_read_full_page(page,minix_get_block);
}

static int ntfs_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata)
{
	int ret;

	ret = block_write_begin(mapping, pos, len, flags, pagep,
				minix_get_block);
	if (unlikely(ret))
		minix_write_failed(mapping, pos + len);

	return ret;
}

static sector_t ntfs_bmap(struct address_space *mapping, sector_t block)
{
	return generic_block_bmap(mapping,block,minix_get_block);
}

static const struct address_space_operations minix_aops = {
	.readpage = ntfs_readpage,
	.writepage = ntfs_writepage,
	.write_begin = ntfs_write_begin,
	.write_end = generic_write_end,
	.bmap = ntfs_bmap
};
#endif

#if 0
static void ntfs_set_inode(struct inode *inode, dev_t rdev)
{
	if (S_ISREG(inode->i_mode)) {
//		inode->i_op = &minix_file_inode_operations;
//		inode->i_fop = &minix_file_operations;
//		inode->i_mapping->a_ops = &minix_aops;
	} else if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &ntfs_dir_inode_operations;;
		inode->i_fop = &ntfs_dir_operations;
//		inode->i_mapping->a_ops = &minix_aops;
	} else if (S_ISLNK(inode->i_mode)) {
//		inode->i_op = &minix_symlink_inode_operations;
//		inode_nohighmem(inode);
//		inode->i_mapping->a_ops = &minix_aops;
	} else
		init_special_inode(inode, inode->i_mode, rdev);
}
#endif


ntfs_inode *ntfs_pathname_to_inode2(ntfs_volume *vol, ntfs_inode *parent,
		const char *pathname)
{
	u64 inum;
	int len, err = 0;
	ntfs_inode *ni;
	struct inode *inode;
	ntfs_inode *result = NULL;
	ntfschar *unicode = NULL;
	char *ascii = NULL;

	if (!vol || !pathname) {
		return ERR_PTR(-EINVAL);
	}
	
	ntfs_log_trace("path: '%s'\n", pathname);

	p = pathname;
	if (parent) {
		ni = parent;
	} else {
		ni = ntfs_inode_open(vol, FILE_root);
		if (IS_ERR(ni)) {
			ntfs_log_debug("Couldn't open the inode of the root "
					"directory.\n");
			err = -EIO;
			result = (ntfs_inode*)NULL;
			goto out;
		}
	}

	len = ntfs_mbstoucs(p, &unicode);
	if (len < 0) {
		ntfs_log_perror("Could not convert filename to Unicode:"
				" '%s'", p);
		err = len;
		goto close;
	} else if (len > NTFS_MAX_NAME_LEN) {
		err = -ENAMETOOLONG;
		goto close;
	}
	inum = ntfs_inode_lookup_by_name(ni, unicode, len);
	if ((s64)inum == (s64) -ENOENT) {
		ntfs_log_debug("Couldn't find name '%s' in pathname "
				"'%s'.\n", p, pathname);
		err = -ENOENT;
		goto close;
	}
	if ((s64)inum < 0)
		goto close;
	if (ni != parent)
		if (ntfs_inode_close(ni)) {
			err = -EIO;
//				err = errno;
			goto out;
		}

	inum = MREF(inum);
	inode = ntfs_iget(vol->sb, inum);
	if (IS_ERR(inode)) {
		ntfs_log_debug("Cannot open inode %llu: %s.\n",
				(unsigned long long)inum, p);
		err = -EIO;
		goto close;
	}
	ni = EXNTFS_I(inode);
	free(unicode);
	unicode = NULL;
	result = ni;
	ni = NULL;

close:
	if (ni && (ni != parent))
		if (ntfs_inode_close(ni) && !err)
			;
//			err = errno;
out:
	free(ascii);
	free(unicode);
	return result ? : ERR_PTR(err);
}

static struct dentry *ntfs_lookup(struct inode *dir, struct dentry *dentry,
				unsigned int flags)
{
	ntfs_log_debug("%s, name=%s\n", __func__, dentry->d_name.name);
	struct inode *inode;
	ntfs_inode *ni = EXNTFS_I(dir);
	ni = ntfs_pathname_to_inode2(ni->vol, ni, dentry->d_name.name);
	ntfs_log_debug("ni=%p\n", ni);
	if (!IS_ERR(ni))
		return d_splice_alias(EXNTFS_V(ni), dentry);

	return (void *)ni;
}

static int ntfs_unlink(struct inode *dir, struct dentry *dentry)
{
	ntfs_log_debug("%s\n", __func__);

	return -EOPNOTSUPP;
}

static int ntfs_symlink(struct inode *dir, struct dentry *dentry, const char *target)
{
	ntfs_log_debug("%s\n", __func__);
	return -EOPNOTSUPP;
}

static int ntfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	ntfs_log_debug("%s\n", __func__);
	return -EOPNOTSUPP;
}

static int ntfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	ntfs_log_debug("%s\n", __func__);
	return -EOPNOTSUPP;
}

static int ntfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			struct inode *new_dir, struct dentry *new_dentry,
			unsigned int flags)
{
	ntfs_log_debug("%s\n", __func__);
	return -EOPNOTSUPP;
}

static int ntfs_setattr(struct dentry *dentry, struct iattr *attr)
{
	ntfs_log_debug("%s\n", __func__);
	return -EOPNOTSUPP;
}

static int ntfs_getattr(const struct path *path, struct kstat *stat,
			 u32 request_mask, unsigned int flags)
{
	struct inode *inode = path->dentry->d_inode;
	ntfs_log_debug("%s, ni=%p\n", __func__, EXNTFS_I(inode));

	generic_fillattr(inode, stat);
	return 0;
}

static int ntfs_update_time(struct inode *inode, struct timespec64 *time, int flags)
{
	return 0;
}

const struct inode_operations ntfs_dir_inode_operations = {
	.create        = __ntfs_create,
	.lookup        = ntfs_lookup,
	.unlink        = ntfs_unlink,
	.symlink       = ntfs_symlink,
	.mkdir         = ntfs_mkdir,
	.rmdir         = ntfs_rmdir,
	.rename        = ntfs_rename,
	.setattr       = ntfs_setattr,
	.getattr       = ntfs_getattr,
	.update_time   = ntfs_update_time,
};

static long ntfs_generic_ioctl(struct file *filp,
		unsigned int cmd, unsigned long arg)
{
	return -EOPNOTSUPP;
}


static int ntfs_filldir(void *dirent, const ntfschar *name,
		const int name_len, const int name_type, const s64 pos,
		const MFT_REF mref, const unsigned dt_type)
{
	char data[128];
	int ret;
	ret = !dir_emit(dirent, (void *)name, name_len, MREF(mref), dt_type);
	memcpy(data, name, name_len);
	data[name_len] = 0;
	ntfs_log_debug("dir_emit %d, name=%s, len=%d\n", ret, data, name_len);
	return ret;
}

static int __ntfs_readdir(struct file *filp, struct dir_context *ctx)
{
	struct inode *inode = file_inode(filp);
	int ret;
	loff_t cpos;
	ntfs_log_debug("%s\n", __func__);
	cpos = ctx->pos;

	ret = ntfs_readdir(EXNTFS_I(inode), &cpos, ctx, ntfs_filldir);
	ctx->pos = cpos;
	ntfs_log_debug("%s, ret=%d\n", __func__, ret);
	return ret;
}

const struct file_operations ntfs_dir_operations = {
	.llseek     = generic_file_llseek,
	.read       = generic_read_dir,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
	.iterate    = __ntfs_readdir,
#else
	.readdir    = __ntfs_readdir,
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
	.ioctl      = ntfs_generic_ioctl,
	.fsync      = ntfs_file_fsync,
#else
	.unlocked_ioctl = ntfs_generic_ioctl,
	.fsync      = generic_file_fsync,
#endif
};

const struct inode_operations ntfs_file_inode_operations = {
	.setattr	= ntfs_setattr,
	.getattr	= ntfs_getattr,
};

const struct file_operations ntfs_file_operations = {
	.llseek		= generic_file_llseek,
	.read_iter	= generic_file_read_iter,
	.write_iter	= generic_file_write_iter,
	.mmap		= generic_file_mmap,
	.fsync		= generic_file_fsync,
	.splice_read	= generic_file_splice_read,
};

static void ntfs_set_inode(struct inode *inode, dev_t rdev)
{
	if (S_ISREG(inode->i_mode)) {
		inode->i_op = &ntfs_file_inode_operations;
		inode->i_fop = &ntfs_file_operations;
//		inode->i_mapping->a_ops = &minix_aops;
	} else if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &ntfs_dir_inode_operations;;
		inode->i_fop = &ntfs_dir_operations;
//		inode->i_mapping->a_ops = &minix_aops;
	} else if (S_ISLNK(inode->i_mode)) {
//		inode->i_op = &minix_symlink_inode_operations;
//		inode_nohighmem(inode);
//		inode->i_mapping->a_ops = &minix_aops;
	} else
		init_special_inode(inode, inode->i_mode, rdev);
}

static ntfs_inode *ntfs_inode_get(struct super_block *sb,
				struct inode *inode, const MFT_REF mref)
{
	s64 l;
	ntfs_inode *ni;
	ntfs_attr_search_ctx *ctx;
	STANDARD_INFORMATION *std_info;
	le32 lthle;
	int err;
	ntfs_volume *vol = sb->s_fs_info;
	ni = EXNTFS_I(inode);

	if (!(inode->i_state & I_NEW)) {
		err = -EINVAL;
		goto err_out;
	}

	ntfs_log_enter("Entering for inode %lld\n", (long long)MREF(mref));
	if (!vol) {
		err = -EINVAL;
		goto err_out;
	}
//	ni = __ntfs_inode_allocate(vol);
//	if (!ni)
//		goto out;
	if (ntfs_file_record_read(vol, mref, &ni->mrec, NULL))
		goto err_out;
	if (!(ni->mrec->flags & MFT_RECORD_IN_USE)) {
		err = -ENOENT;
		goto err_out;
	}
	ni->mft_no = MREF(mref);
	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx)
		goto err_out;
	/* Receive some basic information about inode. */
	if ((err = ntfs_attr_lookup(AT_STANDARD_INFORMATION, AT_UNNAMED,
				0, CASE_SENSITIVE, 0, NULL, 0, ctx))) {
		if (!ni->mrec->base_mft_record)
			ntfs_log_perror("No STANDARD_INFORMATION in base record"
					" %lld", (long long)MREF(mref));
		goto put_err_out;
	}
	std_info = (STANDARD_INFORMATION *)((u8 *)ctx->attr +
			le16_to_cpu(ctx->attr->value_offset));
	ni->flags = std_info->file_attributes;
	ni->creation_time = std_info->creation_time;
	ni->last_data_change_time = std_info->last_data_change_time;
	ni->last_mft_change_time = std_info->last_mft_change_time;
	ni->last_access_time = std_info->last_access_time;
  		/* JPA insert v3 extensions if present */
                /* length may be seen as 72 (v1.x) or 96 (v3.x) */
	lthle = ctx->attr->length;
	if (le32_to_cpu(lthle) > sizeof(STANDARD_INFORMATION)) {
		set_nino_flag(ni, v3_Extensions);
		ni->owner_id = std_info->owner_id;
		ni->security_id = std_info->security_id;
		ni->quota_charged = std_info->quota_charged;
		ni->usn = std_info->usn;
	} else {
		clear_nino_flag(ni, v3_Extensions);
		ni->owner_id = const_cpu_to_le32(0);
		ni->security_id = const_cpu_to_le32(0);
	}
	/* Set attribute list information. */
	if ((err = ntfs_attr_lookup(AT_ATTRIBUTE_LIST, AT_UNNAMED, 0,
			CASE_SENSITIVE, 0, NULL, 0, ctx))) {
		if (err != -ENOENT)
			goto put_err_out;
		/* Attribute list attribute does not present. */
		/* restore previous errno to avoid misinterpretation */
		goto get_size;
	}
	NInoSetAttrList(ni);
	l = ntfs_get_attribute_value_length(ctx->attr);
	if (!l)
		goto put_err_out;
	if (l > 0x40000) {
		err = -EIO;
		ntfs_log_perror("Too large attrlist attribute (%lld), inode "
				"%lld", (long long)l, (long long)MREF(mref));
		goto put_err_out;
	}
	ni->attr_list_size = l;
	ni->attr_list = ntfs_malloc(ni->attr_list_size);
	if (!ni->attr_list)
		goto put_err_out;
	l = ntfs_get_attribute_value(vol, ctx->attr, ni->attr_list);
	if (!l)
		goto put_err_out;
	if (l != ni->attr_list_size) {
		err = -EIO;
		ntfs_log_perror("Unexpected attrlist size (%lld <> %u), inode "
				"%lld", (long long)l, ni->attr_list_size, 
				(long long)MREF(mref));
		goto put_err_out;
	}
get_size:
	if ((err = ntfs_attr_lookup(AT_DATA, AT_UNNAMED, 0, 0, 0, NULL, 0, ctx))) {
		if (err != -ENOENT)
			goto put_err_out;
		if ((err = ntfs_attr_lookup(AT_INDEX_ALLOCATION, NTFS_INDEX_I30, 4, CASE_SENSITIVE, 0, NULL,
				0, ctx))) {
			ntfs_log_perror("Index root attribute missing in directory inode "
					"%lld", (unsigned long long)ni->mft_no);
			goto put_err_out;
		}
		inode->i_size = sle64_to_cpu(ctx->attr->data_size);
		/* Directory or special file. */
		/* restore previous errno to avoid misinterpretation */
		ni->data_size = ni->allocated_size = 0;
	} else {
		if (ctx->attr->non_resident) {
			ni->data_size = sle64_to_cpu(ctx->attr->data_size);
			if (ctx->attr->flags &
					(ATTR_IS_COMPRESSED | ATTR_IS_SPARSE))
				ni->allocated_size = sle64_to_cpu(
						ctx->attr->compressed_size);
			else
				ni->allocated_size = sle64_to_cpu(
						ctx->attr->allocated_size);
		} else {
			ni->data_size = le32_to_cpu(ctx->attr->value_length);
			ni->allocated_size = (ni->data_size + 7) & ~7;
		}
		inode->i_size = ni->data_size;
		set_nino_flag(ni,KnownSize);
	}
	if (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) {
		ntfs_log_leave("is FILE_ATTR_DIRECTORY\n");
		inode->i_mode = S_IFDIR;
	} else {
		inode->i_mode = S_IFREG;
		ntfs_log_leave("is S_IFREG\n");
	}

	set_nlink(inode, le16_to_cpu(ni->mrec->link_count));
	/* Everyone gets all permissions. */
	inode->i_mode |= S_IRWXUGO;
	/* If read-only, no one gets write permissions. */
	if (IS_RDONLY(inode))
		inode->i_mode &= ~S_IWUGO;
	ntfs_set_inode(inode, sb->s_dev);
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	ntfs_attr_put_search_ctx(ctx);
out:
	ntfs_log_leave("ni %p\n", ni);
	return ni;

put_err_out:
	ntfs_attr_put_search_ctx(ctx);
err_out:
//	__ntfs_inode_release(ni);
	ni = NULL;
	goto out;
}

static struct inode *ntfs_iget(struct super_block *sb, unsigned long ino)
{
	struct inode *inode;
	ntfs_inode *ni;

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	if (!ntfs_inode_get(sb, inode, ino))
		goto error_exit;
	unlock_new_inode(inode);
	return inode;

error_exit:
	iget_failed(inode);
	return ERR_PTR(-EIO);
}

static void print_hex(void *data, int len)
{
	int i = 0;
	for (i = 0; i < len; i++)
		printk("%02hhx", ((char *)data)[i]);
	printk("\n");
}

static int ntfs_read_root(struct inode *inode)
{
	inode->i_mode = S_IFDIR;
	inode->i_state = I_NEW;
	inode->i_op = &ntfs_dir_inode_operations;
	inode->i_fop = &ntfs_dir_operations;

	inode->i_generation = 0;
	inode_inc_iversion(inode);
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	unlock_new_inode(inode);
	return 0;
}

static int ntfs_fill_super(struct super_block *sb, void *data, int silent)
{
	ntfs_volume *vol;
	ntfs_inode *ni;
	ntfs_attr_search_ctx *ctx;
	ATTR_RECORD *a;
	struct inode *root_inode = NULL;
	int ret = -ENOMEM;

	sb_set_blocksize(sb, NTFS_BLOCK_SIZE);
	vol = ntfs_device_mount(sb, 0);
	if (!vol)
		goto error_exit;
	sb->s_fs_info = vol;
	sb->s_magic = NTFS_SB_MAGIC;
	sb->s_op = &ntfs_sops;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_max_links = 10000;
	NVolClearShowSysFiles(vol);
	NVolClearShowHidFiles(vol);
#if 0
	ni = ntfs_inode_open(vol, FILE_root);
	if (!ni)
		goto error_exit;
	ntfs_log_debug("############ size=%lld\n", ni->data_size);
	ctx = ntfs_attr_get_search_ctx(ni, ni->mrec);
	if (!ctx) {
		ntfs_log_perror("ntfs_attr_get_search_ctx\n");
		goto error_exit;
	}

	/* Find the index root attribute in the mft record. */
	if (ntfs_attr_lookup(AT_INDEX_ALLOCATION, NTFS_INDEX_I30, 4, CASE_SENSITIVE, 0, NULL,
			0, ctx)) {
		ntfs_log_perror("Index root attribute missing in directory inode "
				"%lld", (unsigned long long)ni->mft_no);
		goto error_exit;
	}

	a = ctx->attr;
	ntfs_log_debug("%d, %d\n", __LINE__, a->non_resident);
	root_inode = &ni->vfs_inode;
	inode_init_once(root_inode);
	inode_init_always(sb, root_inode);
	root_inode->i_size = sle64_to_cpu(a->data_size);
	root_inode->i_ino = FILE_root;
	root_inode->i_blocks = ni->allocated_size >> 9;
	inode_set_iversion(root_inode, 1);
	INIT_LIST_HEAD(&root_inode->i_sb_list);
	inode_sb_list_add(root_inode);
	ntfs_attr_put_search_ctx(ctx);	
	ntfs_log_debug("%d, size=%llu\n", __LINE__, root_inode->i_size);
	ret = ntfs_read_root(root_inode);
	if (ret < 0)
		goto error_exit;

	ntfs_log_debug("%d\n", __LINE__);
	insert_inode_hash(root_inode);
#endif
	root_inode = ntfs_iget(sb, FILE_root);
	if (IS_ERR(root_inode))
		goto error_exit;
	sb->s_root = d_make_root(root_inode);
	if (!sb->s_root)
		goto error_exit;

	ntfs_log_debug("ntfs mount success\n");
	return 0;

error_exit:
	ntfs_log_debug("ntfs mount failed\n");
	if (vol) {
		sb->s_fs_info = NULL;
		ntfs_umount(vol, false);
	}
	return ret;
}

static struct dentry *ntfs_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, ntfs_fill_super);
}

static struct file_system_type ntfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "ntfs-4g",
	.mount		= ntfs_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};

static int __init init_ntfs_fs(void)
{
	int err;

        err = register_filesystem(&ntfs_fs_type);
	if (err)
		goto out;
	return 0;
out:
	return err;
}

static void __exit exit_ntfs_fs(void)
{
	unregister_filesystem(&ntfs_fs_type);
	rcu_barrier();
}
MODULE_AUTHOR("zhangl");
MODULE_DESCRIPTION("NTFS Filesystem based on ntfs-3g");
MODULE_LICENSE("GPL");
module_init(init_ntfs_fs)
module_exit(exit_ntfs_fs)
