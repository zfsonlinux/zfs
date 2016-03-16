dnl #
dnl # Commands common to multiple platforms.  They generally behave
dnl # in the same way and take similar options.
dnl #
AC_DEFUN([ZFS_AC_CONFIG_USER_COMMANDS_COMMON], [
	AC_PATH_TOOL(AWK, awk, "")
	AC_PATH_TOOL(BASENAME, basename, "")
	AC_PATH_TOOL(BC, bc, "")
	AC_PATH_TOOL(BUNZIP2, bunzip2, "")
	AC_PATH_TOOL(BZCAT, bzcat, "")
	AC_PATH_TOOL(CAT, cat, "")
	AC_PATH_TOOL(CD, cd, "cd")		dnl # Builtin in bash
	AC_PATH_TOOL(CHGRP, chgrp, "")
	AC_PATH_TOOL(CHMOD, chmod, "")
	AC_PATH_TOOL(CHOWN, chown, "")
	AC_PATH_TOOL(CKSUM, cksum, "")
	AC_PATH_TOOL(CMP, cmp, "")
	AC_PATH_TOOL(CP, cp, "")
	AC_PATH_TOOL(CPIO, cpio, "")
	AC_PATH_TOOL(CUT, cut, "")
	AC_PATH_TOOL(DATE, date, "")
	AC_PATH_TOOL(DD, dd, "")
	AC_PATH_TOOL(DF, df, "")
	AC_PATH_TOOL(DIFF, diff, "")
	AC_PATH_TOOL(DIRNAME, dirname, "")
	AC_PATH_TOOL(DU, du, "")
	AC_PATH_TOOL(ECHO, echo, "")
	AC_PATH_TOOL(EGREP, egrep, "")
	AC_PATH_TOOL(FDISK, fdisk, "")
	AC_PATH_TOOL(FGREP, fgrep, "")
	AC_PATH_TOOL(FILE, file, "")
	AC_PATH_TOOL(FIND, find, "")
	AC_PATH_TOOL(FSCK, fsck, "")
	AC_PATH_TOOL(GNUDD, dd, "")
	AC_PATH_TOOL(GETCONF, getconf, "")
	AC_PATH_TOOL(GETENT, getent, "")
	AC_PATH_TOOL(GREP, grep, "")
	dnl # Due to permissions unpriviledged users may not detect group*.
	AC_PATH_TOOL(GROUPADD, groupadd, "/usr/sbin/groupadd")
	AC_PATH_TOOL(GROUPDEL, groupdel, "/usr/sbin/groupdel")
	AC_PATH_TOOL(GROUPMOD, groupmod, "/usr/sbin/groupmod")
	AC_PATH_TOOL(HEAD, head, "")
	AC_PATH_TOOL(HOSTNAME, hostname, "")
	AC_PATH_TOOL(ID, id, "")
	AC_PATH_TOOL(KILL, kill, "")
	AC_PATH_TOOL(KSH, ksh, "")
	AC_PATH_TOOL(LOGNAME, logname, "")
	AC_PATH_TOOL(LS, ls, "")
	AC_PATH_TOOL(MD5SUM, md5sum, "")
	AC_PATH_TOOL(MKDIR, mkdir, "")
	AC_PATH_TOOL(MKNOD, mknod, "")
	AC_PATH_TOOL(MKTEMP, mktemp, "")
	AC_PATH_TOOL(MODINFO, modinfo, "")
	AC_PATH_TOOL(MOUNT, mount, "")
	AC_PATH_TOOL(MV, mv, "")
	AC_PATH_TOOL(NAWK, nawk, "")
	AC_PATH_TOOL(PGREP, pgrep, "")
	AC_PATH_TOOL(PING, ping, "")
	AC_PATH_TOOL(PKILL, pkill, "")
	AC_PATH_TOOL(PRINTF, printf, "")
	AC_PATH_TOOL(PS, ps, "")
	AC_PATH_TOOL(PYTHON, python, "")
	AC_PATH_TOOL(REBOOT, reboot, "")
	AC_PATH_TOOL(RMDIR, rmdir, "")
	AC_PATH_TOOL(RSH, rsh, "")
	AC_PATH_TOOL(SED, sed, "")
	AC_PATH_TOOL(SHUF, shuf, "")
	AC_PATH_TOOL(SLEEP, sleep, "")
	AC_PATH_TOOL(SORT, sort, "")
	AC_PATH_TOOL(STRINGS, strings, "")
	AC_PATH_TOOL(SU, su, "")
	AC_PATH_TOOL(SUM, sum, "")
	AC_PATH_TOOL(SYNC, sync, "")
	AC_PATH_TOOL(TAIL, tail, "")
	AC_PATH_TOOL(TAR, tar, "")
	AC_PATH_TOOL(TOUCH, touch, "")
	AC_PATH_TOOL(TR, tr, "")
	AC_PATH_TOOL(TRUE, true, "")
	AC_PATH_TOOL(UMASK, umask, "")
	AC_PATH_TOOL(UMOUNT, umount, "")
	AC_PATH_TOOL(UNAME, uname, "")
	AC_PATH_TOOL(UNIQ, uniq, "")
	dnl # Due to permissions unpriviledged users may not detect user*.
	AC_PATH_TOOL(USERADD, useradd, "/usr/sbin/useradd")
	AC_PATH_TOOL(USERDEL, userdel, "/usr/sbin/userdel")
	AC_PATH_TOOL(USERMOD, usermod, "/usr/sbin/usermod")
	AC_PATH_TOOL(WAIT, wait, "wait") dnl # Builtin in bash
	AC_PATH_TOOL(WC, wc, "")
])

dnl #
dnl # Linux commands, used withing 'is_linux' blocks of test scripts.
dnl # These commands may take different command line arguments.
dnl #
AC_DEFUN([ZFS_AC_CONFIG_USER_COMMANDS_LINUX], [
	AC_PATH_TOOL(BLOCKDEV, blockdev, "")
	AC_PATH_TOOL(COMPRESS, gzip, "")
	AC_PATH_TOOL(FORMAT, parted, "")
	AC_PATH_TOOL(LOCKFS, lsof, "")
	AC_PATH_TOOL(MODUNLOAD, rmmod, "")
	AC_PATH_TOOL(NEWFS, mke2fs, "")
	AC_PATH_TOOL(PFEXEC, sudo, "")
	AC_PATH_TOOL(SHARE, exportfs, "")
	AC_PATH_TOOL(SWAP, swapon, "")
	AC_PATH_TOOL(SWAPADD, swapon, "")
	AC_PATH_TOOL(TRUNCATE, truncate, "")
	AC_PATH_TOOL(UDEVADM, udevadm, "")
	AC_PATH_TOOL(UFSDUMP, dump, "")
	AC_PATH_TOOL(UFSRESTORE, restore, "")
	AC_PATH_TOOL(UNCOMPRESS, gunzip, "")
	AC_PATH_TOOL(UNSHARE, exportfs, "")
	AC_PATH_TOOL(GETFACL, getfacl, "")
	AC_PATH_TOOL(SETFACL, setfacl, "")
	AC_PATH_TOOL(CHACL, chacl, "")
	AC_PATH_TOOL(NPROC, nproc, "")

	PAGESIZE=$($GETCONF PAGESIZE)
	AC_SUBST(PAGESIZE)

	MNTTAB=/etc/mtab
	AC_SUBST(MNTTAB)
])

dnl #
dnl # BSD style commands, these have been kept in case at some point
dnl # we want to build these packages on a BSD style systems.  Otherwise
dnl # they are unused and should be treated as such.
dnl #
AC_DEFUN([ZFS_AC_CONFIG_USER_COMMANDS_BSD], [
	AC_PATH_TOOL(COMPRESS, compress, "")
	AC_PATH_TOOL(COREADM, coreadm, "")
	AC_PATH_TOOL(DIRCMP, dircmp, "")
	AC_PATH_TOOL(DUMPADM, dumpadm, "")
	AC_PATH_TOOL(FORMAT, format, "")
	AC_PATH_TOOL(GETMAJOR, getmajor, "")
	AC_PATH_TOOL(ISAINFO, isainfo, "")
	AC_PATH_TOOL(KSTAT, kstat, "")
	AC_PATH_TOOL(LOCKFS, lockfs, "")
	AC_PATH_TOOL(LOFIADM, lofiadm, "")
	AC_PATH_TOOL(MODUNLOAD, modunload, "")
	AC_PATH_TOOL(NEWFS, newfs, "")
	AC_PATH_TOOL(PAGESIZE, pagesize, "")
	AC_PATH_TOOL(PFEXEC, pfexec, "")
	AC_PATH_TOOL(PKGINFO, pkginfo, "")
	AC_PATH_TOOL(PRTVTOC, prtvtoc, "")
	AC_PATH_TOOL(PSRINFO, psrinfo, "")
	AC_PATH_TOOL(SHARE, share, "")
	AC_PATH_TOOL(SVCADM, svcadm, "")
	AC_PATH_TOOL(SVCS, svcs, "")
	AC_PATH_TOOL(SWAP, swap, "")
	AC_PATH_TOOL(SWAPADD, swapadd, "")
	AC_PATH_TOOL(UFSDUMP, ufsdump, "")
	AC_PATH_TOOL(UFSRESTORE, ufsrestore, "")
	AC_PATH_TOOL(UMOUNTALL, umountall, "")
	AC_PATH_TOOL(UNCOMPRESS, uncompress, "")
	AC_PATH_TOOL(UNSHARE, unshare, "")
	AC_PATH_TOOL(ZONEADM, zoneadm, "")
	AC_PATH_TOOL(ZONECFG, zonecfg, "")
	AC_PATH_TOOL(ZONENAME, zonename, "")
])

AC_DEFUN([ZFS_AC_CONFIG_USER_COMMANDS], [
	ZFS_AC_CONFIG_USER_COMMANDS_COMMON

	OS=$($UNAME -o)
	AS_IF([test "$OS" == "GNU/Linux"], [
		ZFS_AC_CONFIG_USER_COMMANDS_LINUX
	], [
		ZFS_AC_CONFIG_USER_COMMANDS_BSD
	])
])
