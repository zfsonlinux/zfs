include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

lib_LTLIBRARIES = libdiskmgt.la

libdiskmgt_la_SOURCES = \
	dm.c \
	libdiskmgt.c \
	diskutil.c \
	entry.c \
	inuse_corestorage.c \
	inuse_fs.c \
	inuse_macswap.c \
	inuse_mnt.c \
	inuse_partition.c \
	inuse_zpool.c \
	slice.c

libdiskmgt_la_LDFLAGS = -version-info 1:0:0 -framework DiskArbitration -framework CoreServices

EXTRA_DIST = $(USER_C)
