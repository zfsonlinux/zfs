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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Copyright (c) 2012 by Delphix. All rights reserved.
#

. $STF_SUITE/include/libtest.shlib

#
# DESCRIPTION:
#	Verify debugging features of zpool such as ABORT and freeze/unfreeze
#	should run successfully.
#
# STRATEGY:
# 1. Create an array containg each zpool options.
# 2. For each element, execute the zpool command.
# 3. Verify it run successfully.
#

verify_runnable "both"

log_assert "Debugging features of zpool should succeed."

log_must $ZPOOL -? > /dev/null 2>&1

if is_global_zone ; then
	log_must $ZPOOL freeze $TESTPOOL
else
	log_mustnot $ZPOOL freeze $TESTPOOL
	log_mustnot $ZPOOL freeze ${TESTPOOL%%/*}
fi

log_mustnot $ZPOOL freeze fakepool

# Remove corefile possibly left by previous failing run of this test.
[[ -f core ]] && log_must rm -f core

if is_linux; then
        ulimit -c unlimited
        echo "core" >/proc/sys/kernel/core_pattern
        echo 0 >/proc/sys/kernel/core_uses_pid
fi

ZFS_ABORT=1; export ZFS_ABORT
$ZPOOL > /dev/null 2>&1
unset ZFS_ABORT

[[ -f core ]] || log_fail "$ZPOOL did not dump core by request."
[[ -f core ]] && log_must rm -f core

log_pass "Debugging features of zpool succeed."
