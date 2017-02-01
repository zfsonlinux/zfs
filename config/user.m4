dnl #
dnl # Default ZFS user configuration
dnl #
AC_DEFUN([ZFS_AC_CONFIG_USER], [
	ZFS_AC_CONFIG_USER_MOUNT_HELPER
	ZFS_AC_CONFIG_USER_UDEV
	ZFS_AC_CONFIG_USER_SYSTEMD
	ZFS_AC_CONFIG_USER_SYSVINIT
	ZFS_AC_CONFIG_USER_DRACUT
	ZFS_AC_CONFIG_USER_ARCH
	ZFS_AC_CONFIG_USER_ZLIB
	ZFS_AC_CONFIG_USER_LIBUUID
	ZFS_AC_CONFIG_USER_LIBBLKID
	ZFS_AC_CONFIG_USER_LIBATTR
	ZFS_AC_CONFIG_USER_FRAME_LARGER_THAN
	ZFS_AC_CONFIG_USER_RUNSTATEDIR
	ZFS_AC_CONFIG_USER_MAKEDEV_IN_SYSMACROS
	ZFS_AC_CONFIG_USER_MAKEDEV_IN_MKDEV
	ZFS_AC_CONFIG_USER_NO_FORMAT_TRUNCATION
	ZFS_AC_CONFIG_USER_COMMANDS
	ZFS_AC_TEST_FRAMEWORK
dnl #
dnl #	Checks for library functions
	AC_CHECK_FUNCS([mlockall])
])

dnl #
dnl # Setup the environment for the ZFS Test Suite.  Currently only
dnl # Linux sytle systems are supported but this infrastructure can
dnl # be extended to support other platforms if needed.
dnl #
AC_DEFUN([ZFS_AC_TEST_FRAMEWORK], [
	ZONENAME="echo global"
	AC_SUBST(ZONENAME)

	AC_SUBST(RM)
])
