#!/bin/ksh -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Copyright (c) 2013, 2016 by Delphix. All rights reserved.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/inuse/inuse.cfg

#
# DESCRIPTION:
# Newfs will interfere with devices and spare devices that are in use
# by exported pool.
#
# STRATEGY:
# 1. Create a regular|mirror|raidz|raidz2 pool with the given disk
# 2. Export the pool
# 3. Try to newfs against the disk, verify it succeeds as expect.
#

verify_runnable "global"

if ! is_physical_device $FS_DISK0; then
	log_unsupported "This directory cannot be run on raw files."
fi

function cleanup
{
	poolexists $TESTPOOL1 || zpool import $TESTPOOL1 >/dev/null 2>&1

	poolexists $TESTPOOL1 && destroy_pool $TESTPOOL1

	#
	# Tidy up the disks we used.
	#
	cleanup_devices $vdisks $sdisks
}

function verify_assertion # disks
{
	typeset targets=$1

	for t in $targets; do
		if ! new_fs $t; then
			log_fail "newfs over exported pool " \
				"fails unexpectedly."
		fi
	done

	return 0
}

log_assert "Verify newfs over exported pool succeed."

log_onexit cleanup

set -A vdevs "" "mirror" "raidz" "raidz1" "raidz2"

typeset -i i=0
typeset cyl=""

for num in 0 1 2 3 ; do
	eval typeset disk=\${FS_DISK$num}
	zero_partitions $disk
done

while (( i < ${#vdevs[*]} )); do
	create_pool $TESTPOOL1 ${vdevs[i]} $vdisks spare $sdisks
	log_must zpool export $TESTPOOL1
	verify_assertion "$rawtargets"

	(( i = i + 1 ))
done

log_pass "Newfs over exported pool succeed."
