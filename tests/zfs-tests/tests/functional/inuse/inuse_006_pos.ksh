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
# Copyright (c) 2013 by Delphix. All rights reserved.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/inuse/inuse.cfg

#
# DESCRIPTION:
# dumpadm will not interfere with devices and spare devices that are in use
# by active pool.
#
# STRATEGY:
# 1. Create a regular|mirror|raidz|raidz2 pool with the given disk
# 2. Try to dumpadm against the disk, verify it fails as expect.
#

verify_runnable "global"

function cleanup
{
	if [[ -n $PREVDUMPDEV ]]; then
		log_must $DUMPADM -u -d $PREVDUMPDEV
	fi

	poolexists $TESTPOOL1 && destroy_pool $TESTPOOL1

	#
	# Tidy up the disks we used.
	#
	cleanup_devices $vdisks $sdisks
}

function verify_assertion #slices
{
	typeset targets=$1

	for t in $targets; do
		log_mustnot $DUMPADM -d $t
	done

        return 0
}

log_assert "Verify dumpadm over active pool fails."

log_onexit cleanup

set -A vdevs "" "mirror" "raidz" "raidz1" "raidz2"

typeset -i i=0

PREVDUMPDEV=`$DUMPADM | $GREP "Dump device" | $AWK '{print $3}'`

while (( i < ${#vdevs[*]} )); do

	for num in 0 1 2 3 ; do
		eval typeset slice=\${FS_SIDE$num}
		disk=${slice%${SLICE_PREFIX}*}
		slice=${slice##*${SLICE_PREFIX}}
		if [[ $WRAPPER == *"smi"* && \
			$disk == ${saved_disk} ]]; then
			cyl=$(get_endslice $disk ${saved_slice})
			log_must set_partition $slice "$cyl" $FS_SIZE $disk
		else
			log_must set_partition $slice "" $FS_SIZE $disk
		fi
		saved_disk=$disk
		saved_slice=$slice
	done

	if [[ -n $SINGLE_DISK && -n ${vdevs[i]} ]]; then
		(( i = i + 1 ))
		continue
	fi

	create_pool $TESTPOOL1 ${vdevs[i]} $vslices spare $sslices
	verify_assertion "$disktargets"
	destroy_pool $TESTPOOL1

	if [[ ( $FS_DISK0 == $FS_DISK2 ) && -n ${vdevs[i]} ]]; then
		(( i = i + 1 ))
		continue
	fi

	if [[ ( $FS_DISK0 == $FS_DISK3 ) && ( ${vdevs[i]} == "raidz2" ) ]]; then
		(( i = i + 1 ))
		continue
	fi

	create_pool $TESTPOOL1 ${vdevs[i]} $vdisks spare $sdisks
	verify_assertion "$disktargets"
	destroy_pool $TESTPOOL1

	(( i = i + 1 ))
done

log_pass "Dumpadm over active pool fails."
