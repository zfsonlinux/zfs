#!/bin/ksh

#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright (c) 2014, 2016 by Delphix. All rights reserved.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/rsend/rsend.kshlib

#
# Description:
# Verify resumability of a full and incremental ZFS send/receive with the
# -e (embedded) flag in the presence of a corrupted stream.
#
# Strategy:
# 1. Start a full ZFS send with the -e flag (embedded), redirect output to
#    a file
# 2. Mess up the contents of the stream state file on disk
# 3. Try ZFS receive, which should fail with a checksum mismatch error
# 4. ZFS send to the stream state file again using the receive_resume_token
# 5. ZFS receive and verify the receive completes successfully
# 6. Repeat steps on an incremental ZFS send
#

verify_runnable "both"

log_assert "Verify resumability of a full and incremental ZFS send/receive " \
    "with the -e (embedded) flag"
log_onexit cleanup_pool $POOL2

sendfs=$POOL/sendfs
recvfs=$POOL2/recvfs
streamfs=$POOL/stream

test_fs_setup $POOL $POOL2
resume_test "zfs send -v -e $sendfs@a" $streamfs $recvfs
resume_test "zfs send -v -e -i @a $sendfs@b" $streamfs $recvfs
file_check $sendfs $recvfs

log_pass "Verify resumability of a full and incremental ZFS send/receive " \
    "with the -e (embedded) flag"
