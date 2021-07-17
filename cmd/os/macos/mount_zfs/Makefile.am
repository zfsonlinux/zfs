include $(top_srcdir)/config/Rules.am

FS_BUNDLEPREFIX = /Library/Filesystems
FS_BUNDLEDIR = $(DESTDIR)$(FS_BUNDLEPREFIX)/zfs.fs

sbin_PROGRAMS = mount_zfs

AM_CPPFLAGS += -I$(top_srcdir)/lib/libzfs

mount_zfs_SOURCES = \
	mount_zfs.c

mount_zfs_LDADD = \
	$(abs_top_builddir)/lib/libzfs/libzfs.la \
	$(abs_top_builddir)/lib/libzfs_core/libzfs_core.la \
	$(abs_top_builddir)/lib/libnvpair/libnvpair.la

mount_zfs_LDADD += $(LTLIBINTL)

include $(top_srcdir)/config/CppCheck.am

install-exec-hook:
	cp -f $(DESTDIR)/$(sbindir)/mount_zfs $(FS_BUNDLEDIR)/Contents/Resources/mount_zfs
