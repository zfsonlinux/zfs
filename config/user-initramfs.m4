AC_DEFUN([ZFS_AC_CONFIG_USER_INITRAMFS], [
	AC_ARG_ENABLE(initramfs,
		AC_HELP_STRING([--enable-initramfs],
		[install initramfs-tools files [[default: yes]]]),
		[enable_initramfs=$enableval],
		[enable_initramfs=yes])

	AC_MSG_CHECKING(for initramfs support)
	AC_MSG_RESULT([$enable_initramfs])

	AS_IF([test "x$enable_initramfs" = xyes], [
		ZFS_INITRAMFS=initramfs
	])

	AC_SUBST(ZFS_INITRAMFS)
])
