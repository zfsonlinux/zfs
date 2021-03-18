#!/bin/ksh -p
#
# DDL HEADER START
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
# Copyright (c) 2021 by Lawrence Livermore National Security, LLC.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/direct/dio.cfg
. $STF_SUITE/tests/functional/direct/dio.kshlib

#
# DESCRIPTION:
# 	Verify mixed direct IO and mmap IO.
#
# STRATEGY:
#	1. Create an empty.
#	2. Start a background fio randomly direct writing to the file.
#	3. Start a background fio randomly mmap writing to the file.
#

verify_runnable "global"

function cleanup
{
	log_must rm -f "$tmp_file"
}

log_assert "Verify mixed direct IO and mmap IO"

log_onexit cleanup

mntpnt=$(get_prop mountpoint $TESTPOOL/$TESTFS)
tmp_file=$mntpnt/file
bs=$((1024 * 1024))
blocks=32
size=$((bs * blocks))
runtime=10

log_must stride_dd -i /dev/zero -o $tmp_file -b $bs -c $blocks

# Direct IO writes
log_must eval "fio --filename=$tmp_file --name=direct-write \
	--rw=write --size=$size --bs=$bs --direct=1 --numjobs=1 \
	--ioengine=sync --fallocate=none --verify=sha1 \
	--group_reporting --minimal --runtime=$runtime --time_based &"

# Direct IO reads
log_must eval "fio --filename=$tmp_file --name=direct-read \
	--rw=read --size=$size --bs=$bs --direct=1 --numjobs=1 \
	--ioengine=sync --fallocate=none --verify=sha1 \
	--group_reporting --minimal --runtime=$runtime --time_based &"

# mmap IO writes
log_must eval "fio --filename=$tmp_file --name=mmap-write \
	--rw=write --size=$size --bs=$bs --numjobs=1 \
	--ioengine=mmap --fallocate=none --verify=sha1 \
	--group_reporting --minimal --runtime=$runtime --time_based &"

# mmap IO reads
log_must eval "fio --filename=$tmp_file --name=mmap-read \
	--rw=read --size=$size --bs=$bs --numjobs=1 \
	--ioengine=mmap --fallocate=none --verify=sha1 \
	--group_reporting --minimal --runtime=$runtime --time_based &"

wait

log_pass "Verfied mixed direct IO and mmap IO"
