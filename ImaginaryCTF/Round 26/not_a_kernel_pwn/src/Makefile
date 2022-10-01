build: vm/mount
#	cd vm/mount; cpio -idv < ../rootfs.cpio
	cd vm/mount; find . -print0 | cpio -o --null --format=newc --owner root > ../rootfs.cpio
