dnl #
dnl # 5.12 API change,
dnl # inode_owner_or_capable() now takes struct user_namespace *
dnl # to support idmapped mounts
dnl #
AC_DEFUN([ZFS_AC_KERNEL_SRC_INODE_OWNER_OR_CAPABLE], [
	ZFS_LINUX_TEST_SRC([inode_owner_or_capable_idmapped], [
		#include <linux/fs.h>
	],[
		struct inode *ip = NULL;
		(void) inode_owner_or_capable(&init_user_ns, ip);
	])
])

AC_DEFUN([ZFS_AC_KERNEL_INODE_OWNER_OR_CAPABLE], [
	AC_MSG_CHECKING(
	    [whether inode_owner_or_capable() takes user_ns])
	ZFS_LINUX_TEST_RESULT([inode_owner_or_capable_idmapped], [
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_INODE_OWNER_OR_CAPABLE_IDMAPPED, 1,
		    [inode_owner_or_capable() takes user_ns])
	],[
		AC_MSG_RESULT(no)
	])
])
