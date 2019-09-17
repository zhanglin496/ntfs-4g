
obj-m := ntfs-4g.o
ntfs-4g-objs += misc.o bootsect.o volume.o attrib.o inode.o dir.o runlist.o index.o \
		mst.o mft.o lcnalloc.o compress.o xattrs.o bitmap.o security.o unistr.o \
		efs.o attrlist.o ea.o device.o collate.o reparse.o object_id.o logfile.o \
		acls.o cache.o debug.o super.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	rm -f *.ko *.o *.mod.o *.mod.c *.symvers

