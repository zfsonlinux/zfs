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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

. $STF_SUITE/include/libtest.shlib

#
# DESCRIPTION:
#	Verify recursive snapshotting could not break ZFS.
#
# STRATEGY:
#	1. Create deeply-nested filesystems until it is too long to create snap
#	2. Verify zfs snapshot -r pool@snap will not break ZFS
#

verify_runnable "both"

function cleanup
{
	if datasetexists $initfs ; then
		log_must $ZFS destroy -rf $initfs
	fi
}

log_assert "Verify recursive snapshotting could not break ZFS."
log_onexit cleanup

initfs=$TESTPOOL/$TESTFS/$TESTFS
basefs=$initfs
typeset -i ret=0 len snaplen
while ((ret == 0)); do
	$ZFS create $basefs
	$ZFS snapshot $basefs@snap1
	ret=$?

	if ((ret != 0)); then
		len=$($ECHO $basefs| $WC -c)
		log_note "The deeply-nested filesystem len: $len"

		#
		# Make sure there are at lease 2 characters left
		# for snapshot name space, otherwise snapshot name
		# is incorrect
		#
		if ((len >= 255)); then
			if datasetexists $basefs; then
				log_must $ZFS destroy -r $basefs
			fi
			basefs=${basefs%/*}
			len=$($ECHO $basefs| $WC -c)
		fi
		break
	fi

	basefs=$basefs/$TESTFS
done

# Make snapshot name is longer than the max length
((snaplen = 256 - len + 10))
snap=$(gen_dataset_name $snaplen "s")
log_mustnot $ZFS snapshot -r $TESTPOOL@$snap

log_must datasetnonexists $TESTPOOL@$snap
while [[ $basefs != $TESTPOOL ]]; do
	log_must datasetnonexists $basefs@$snap
	basefs=${basefs%/*}
done

log_pass "Verify recursive snapshotting could not break ZFS."
