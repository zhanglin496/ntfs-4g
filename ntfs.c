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
//#include <linux/iversion.h>
#include <linux/version.h>

#include "logging.h"
#include "layout.h"
#include "bootsect.h"

static void print_hex(void *data, int len)
{
	int i = 0;
	for (i = 0; i < len; i++)
		printk("%02hhx", ((char *)data)[i]);
	printk("\n");
}

static int ntfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct buffer_head *bh;
	NTFS_BOOT_SECTOR *bs;
	ntfs_volume *vol;
	int ret = -ENOMEM;

	if (!(bh = sb_bread(sb, 0))) {
		goto error_exit;
	}
	if (bh->b_size < sizeof(*bs))
		goto error_exit;

	sb_set_blocksize(sb, NTFS_BLOCK_SIZE);
	bs = (void *)bh->b_data;
	print_hex(bs, 1024);
	brelse(bh);

	if (!(bh = sb_bread(sb, 1)))
		goto error_exit;
	bs = (void *)bh->b_data;
	print_hex(bs, 512);

//	vol = ntfs_volume_startup(sb, 0);
	vol = ntfs_device_mount(sb, 0);
	if (!vol)
		goto error_exit;
	ntfs_log_debug("ntfs_volume_startup success\n");

error_exit:
	kfree(vol);
	brelse(bh);
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
}

MODULE_AUTHOR("zhangl");
MODULE_DESCRIPTION("NTFS Filesystem based on ntfs-3g");
MODULE_LICENSE("GPL");
module_init(init_ntfs_fs)
module_exit(exit_ntfs_fs)
