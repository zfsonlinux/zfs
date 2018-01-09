#!/bin/bash

#
# CDDL HEADER START
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
# CDDL HEADER END
#

#
# Copyright (c) 2015 by Delphix. All rights reserved.
# Copyright (C) 2016 Lawrence Livermore National Security, LLC.
#

BASE_DIR=$(dirname "$0")
SCRIPT_COMMON=common.sh
if [ -f "${BASE_DIR}/${SCRIPT_COMMON}" ]; then
	. "${BASE_DIR}/${SCRIPT_COMMON}"
else
	echo "Missing helper script ${SCRIPT_COMMON}" && exit 1
fi

# shellcheck disable=SC2034
PROG=zloop.sh

DEFAULTWORKDIR=/var/tmp
DEFAULTCOREDIR=/var/tmp/zloop

function usage
{
	echo -e "\n$0 [-t <timeout>] [ -s <vdev size> ] [-c <dump directory>]" \
	    "[ -- [extra ztest parameters]]\n" \
	    "\n" \
	    "  This script runs ztest repeatedly with randomized arguments.\n" \
	    "  If a crash is encountered, the ztest logs, any associated\n" \
	    "  vdev files, and core file (if one exists) are moved to the\n" \
	    "  output directory ($DEFAULTCOREDIR by default). Any options\n" \
	    "  after the -- end-of-options marker will be passed to ztest.\n" \
	    "\n" \
	    "  Options:\n" \
	    "    -t  Total time to loop for, in seconds. If not provided,\n" \
	    "        zloop runs forever.\n" \
	    "    -s  Size of vdev devices.\n" \
	    "    -f  Specify working directory for ztest vdev files.\n" \
	    "    -c  Specify a core dump directory to use.\n" \
	    "    -h  Print this help message.\n" \
	    "" >&2
}

function or_die
{
	# shellcheck disable=SC2068
	$@
	# shellcheck disable=SC2181
	if [[ $? -ne 0 ]]; then
		# shellcheck disable=SC2145
		echo "Command failed: $@"
		exit 1
	fi
}

# core file helpers
origcorepattern="$(cat /proc/sys/kernel/core_pattern)"
coreglob="$(egrep -o '^([^|%[:space:]]*)' /proc/sys/kernel/core_pattern)*"

if [[ $coreglob = "*" ]]; then
        echo "Setting core file pattern..."
        echo "core" > /proc/sys/kernel/core_pattern
        coreglob="$(egrep -o '^([^|%[:space:]]*)' \
            /proc/sys/kernel/core_pattern)*"
fi

function core_file
{
	# shellcheck disable=SC2012 disable=2086
        printf "%s" "$(ls -tr1 $coreglob 2> /dev/null | head -1)"
}

function core_prog
{
	prog=$ZTEST
	core_id=$($GDB --batch -c "$1" | grep "Core was generated by" | \
	    tr  \' ' ')
	# shellcheck disable=SC2076
	if [[ "$core_id" =~ "zdb "  ]]; then
		prog=$ZDB
	fi
	printf "%s" "$prog"
}

function store_core
{
	core="$(core_file)"
	if [[ $ztrc -ne 0 ]] || [[ -f "$core" ]]; then
		df -h "$workdir" >>ztest.out
		coreid=$(date "+zloop-%y%m%d-%H%M%S")
		foundcrashes=$((foundcrashes + 1))

		dest=$coredir/$coreid
		or_die mkdir -p "$dest"
		or_die mkdir -p "$dest/vdev"

		echo "*** ztest crash found - moving logs to $dest"

		or_die mv ztest.history "$dest/"
		or_die mv ztest.ddt "$dest/"
		or_die mv ztest.out "$dest/"
		or_die mv "$workdir/ztest*" "$dest/vdev/"
		or_die mv "$workdir/zpool.cache" "$dest/vdev/"

		# check for core
		if [[ -f "$core" ]]; then
			coreprog=$(core_prog "$core")
			corestatus=$($GDB --batch --quiet \
			    -ex "set print thread-events off" \
			    -ex "printf \"*\n* Backtrace \n*\n\"" \
			    -ex "bt" \
			    -ex "printf \"*\n* Libraries \n*\n\"" \
			    -ex "info sharedlib" \
			    -ex "printf \"*\n* Threads (full) \n*\n\"" \
			    -ex "info threads" \
			    -ex "printf \"*\n* Backtraces \n*\n\"" \
			    -ex "thread apply all bt" \
			    -ex "printf \"*\n* Backtraces (full) \n*\n\"" \
			    -ex "thread apply all bt full" \
			    -ex "quit" "$coreprog" "$core" | grep -v "New LWP")

			# Dump core + logs to stored directory
			echo "$corestatus" >>"$dest/status"
			or_die mv "$core" "$dest/"

			# Record info in cores logfile
			echo "*** core @ $coredir/$coreid/$core:" | \
			    tee -a ztest.cores
			echo "$corestatus" | tee -a ztest.cores
			echo "" | tee -a ztest.cores
		fi
		echo "continuing..."
	fi
}

rngdpid=""
function on_exit
{
	if [ -n "$rngdpid" ]; then
		kill -9 "$rngdpid"
	fi
}
trap on_exit EXIT

# parse arguments
# expected format: zloop [-t timeout] [-c coredir] [-- extra ztest args]
coredir=$DEFAULTCOREDIR
basedir=$DEFAULTWORKDIR
rundir="zloop-run"
timeout=0
size="512m"
while getopts ":ht:s:c:f:" opt; do
	case $opt in
		t ) [[ $OPTARG -gt 0 ]] && timeout=$OPTARG ;;
		s ) [[ $OPTARG ]] && size=$OPTARG ;;
		c ) [[ $OPTARG ]] && coredir=$OPTARG ;;
		f ) [[ $OPTARG ]] && basedir=$(readlink -f "$OPTARG") ;;
		h ) usage
		    exit 2
		    ;;
		* ) echo "Invalid argument: -$OPTARG";
		    usage
		    exit 1
	esac
done
# pass remaining arguments on to ztest
shift $((OPTIND - 1))

# enable core dumps
ulimit -c unlimited
export ASAN_OPTIONS=abort_on_error=1:disable_coredump=0

if [[ -f "$(core_file)" ]]; then
	echo -n "There's a core dump here you might want to look at first... "
	core_file
	exit 1
fi

if [[ ! -d $coredir ]]; then
	echo "core dump directory ($coredir) does not exist, creating it."
	or_die mkdir -p "$coredir"
fi

if [[ ! -w $coredir ]]; then
	echo "core dump directory ($coredir) is not writable."
	exit 1
fi

or_die rm -f ztest.history
or_die rm -f ztest.ddt
or_die rm -f ztest.cores

# start rngd in the background so we don't run out of entropy
or_die read -r rngdpid < <(rngd -f -r /dev/urandom & echo $!)

ztrc=0		# ztest return value
foundcrashes=0	# number of crashes found so far
starttime=$(date +%s)
curtime=$starttime

# if no timeout was specified, loop forever.
while [[ $timeout -eq 0 ]] || [[ $curtime -le $((starttime + timeout)) ]]; do
	zopt="-VVVVV"

	# start each run with an empty directory
	workdir="$basedir/$rundir"
	or_die rm -rf "$workdir"
	or_die mkdir "$workdir"

	# switch between common arrangements & fully randomized
	if [[ $((RANDOM % 2)) -eq 0 ]]; then
		mirrors=2
		raidz=0
		parity=1
		vdevs=2
	else
		mirrors=$(((RANDOM % 3) * 1))
		parity=$(((RANDOM % 3) + 1))
		raidz=$((((RANDOM % 9) + parity + 1) * (RANDOM % 2)))
		vdevs=$(((RANDOM % 3) + 3))
	fi
	align=$(((RANDOM % 2) * 3 + 9))
	runtime=$((RANDOM % 100))
	passtime=$((RANDOM % (runtime / 3 + 1) + 10))

	zopt="$zopt -m $mirrors"
	zopt="$zopt -r $raidz"
	zopt="$zopt -R $parity"
	zopt="$zopt -v $vdevs"
	zopt="$zopt -a $align"
	zopt="$zopt -T $runtime"
	zopt="$zopt -P $passtime"
	zopt="$zopt -s $size"
	zopt="$zopt -f $workdir"

	# shellcheck disable=SC2124
	cmd="$ZTEST $zopt $@"
	desc="$(date '+%m/%d %T') $cmd"
	echo "$desc" | tee -a ztest.history
	echo "$desc" >>ztest.out
	$cmd >>ztest.out 2>&1
	ztrc=$?
	egrep '===|WARNING' ztest.out >>ztest.history
	$ZDB -U "$workdir/zpool.cache" -DD ztest >>ztest.ddt 2>&1

	store_core

	curtime=$(date +%s)
done

echo "zloop finished, $foundcrashes crashes found"

#restore core pattern
echo "$origcorepattern" > /proc/sys/kernel/core_pattern

uptime >>ztest.out

if [[ $foundcrashes -gt 0 ]]; then
	exit 1
fi
