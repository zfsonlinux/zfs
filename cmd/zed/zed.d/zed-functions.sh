# zed-functions.sh
#
# ZED helper functions for use in ZEDLETs


# Variable Defaults
#
: "${ZED_EMAIL_INTERVAL_SECS:=3600}"
: "${ZED_EMAIL_VERBOSE:=0}"
: "${ZED_LOCKDIR:="/var/lock"}"
: "${ZED_RUNDIR:="/var/run"}"
: "${ZED_SYSLOG_PRIORITY:="daemon.notice"}"
: "${ZED_SYSLOG_TAG:="zed"}"

ZED_FLOCK_FD=8


# zed_check_cmd (cmd, ...)
#
# For each argument given, search PATH for the executable command [cmd].
# Log a message if [cmd] is not found.
#
# Arguments
#   cmd: name of executable command for which to search
#
# Return
#   0 if all commands are found in PATH and are executable
#   n for a count of the command executables that are not found
#
zed_check_cmd()
{
    local cmd
    local rv=0

    for cmd; do
        if ! command -v "${cmd}" >/dev/null 2>&1; then
            zed_log_err "\"${cmd}\" not installed"
            rv=$((rv + 1))
        fi
    done
    return "${rv}"
}


# zed_log_msg (msg, ...)
#
# Write all argument strings to the system log.
#
# Globals
#   ZED_SYSLOG_PRIORITY
#   ZED_SYSLOG_TAG
#
# Return
#   nothing
#
zed_log_msg()
{
    logger -p "${ZED_SYSLOG_PRIORITY}" -t "${ZED_SYSLOG_TAG}" -- "$@"
}


# zed_log_err (msg, ...)
#
# Write an error message to the system log.  This message will contain the
# script name, EID, and all argument strings.
#
# Globals
#   ZED_SYSLOG_PRIORITY
#   ZED_SYSLOG_TAG
#   ZEVENT_EID
#
# Return
#   nothing
#
zed_log_err()
{
    logger -p "${ZED_SYSLOG_PRIORITY}" -t "${ZED_SYSLOG_TAG}" -- "error:" \
        "$(basename -- "$0"):" "${ZEVENT_EID:+"eid=${ZEVENT_EID}:"}" "$@"
}


# zed_lock (lockfile, [fd])
#
# Obtain an exclusive (write) lock on [lockfile].  If the lock cannot be
# immediately acquired, wait until it becomes available.
#
# Every zed_lock() must be paired with a corresponding zed_unlock().
#
# By default, flock-style locks associate the lockfile with file descriptor 8.
# The bash manpage warns that file descriptors >9 should be used with care as
# they may conflict with file descriptors used internally by the shell.  File
# descriptor 9 is reserved for zed_rate_limit().  If concurrent locks are held
# within the same process, they must use different file descriptors (preferably
# decrementing from 8); otherwise, obtaining a new lock with a given file
# descriptor will release the previous lock associated with that descriptor.
#
# Arguments
#   lockfile: pathname of the lock file; the lock will be stored in
#     ZED_LOCKDIR unless the pathname contains a "/".
#   fd: integer for the file descriptor used by flock (OPTIONAL unless holding
#     concurrent locks)
#
# Globals
#   ZED_FLOCK_FD
#   ZED_LOCKDIR
#
# Return
#   nothing
#
zed_lock()
{
    local lockfile="$1"
    local fd="${2:-${ZED_FLOCK_FD}}"
    local umask_bak
    local err

    [ -n "${lockfile}" ] || return
    if ! expr "${lockfile}" : '.*/' >/dev/null 2>&1; then
        lockfile="${ZED_LOCKDIR}/${lockfile}"
    fi

    umask_bak="$(umask)"
    umask 077

    # Obtain a lock on the file bound to the given file descriptor.
    #
    eval "exec ${fd}> '${lockfile}'"
    err="$(flock --exclusive "${fd}" 2>&1)"
    if [ $? -ne 0 ]; then
        zed_log_err "failed to lock \"${lockfile}\": ${err}"
    fi

    umask "${umask_bak}"
}


# zed_unlock (lockfile, [fd])
#
# Release the lock on [lockfile].
#
# Arguments
#   lockfile: pathname of the lock file
#   fd: integer for the file descriptor used by flock (must match the file
#     descriptor passed to the zed_lock function call)
#
# Globals
#   ZED_FLOCK_FD
#   ZED_LOCKDIR
#
# Return
#   nothing
#
zed_unlock()
{
    local lockfile="$1"
    local fd="${2:-${ZED_FLOCK_FD}}"
    local err

    [ -n "${lockfile}" ] || return
    if ! expr "${lockfile}" : '.*/' >/dev/null 2>&1; then
        lockfile="${ZED_LOCKDIR}/${lockfile}"
    fi

    # Release the lock and close the file descriptor.
    #
    err="$(flock --unlock "${fd}" 2>&1)"
    if [ $? -ne 0 ]; then
        zed_log_err "failed to unlock \"${lockfile}\": ${err}"
    fi
    eval "exec ${fd}>&-"
}


# zed_rate_limit (tag, [interval])
#
# Check whether an event of a given type [tag] has already occurred within the
# last [interval] seconds.
#
# This function obtains a lock on the statefile using file descriptor 9.
#
# Arguments
#   tag: arbitrary string for grouping related events to rate-limit
#   interval: time interval in seconds (OPTIONAL)
#
# Globals
#   ZED_EMAIL_INTERVAL_SECS
#   ZED_RUNDIR
#
# Return
#   0 if the event should be processed
#   1 if the event should be dropped
#
# State File Format
#   time;tag
#
zed_rate_limit()
{
    local tag="$1"
    local interval="${2:-${ZED_EMAIL_INTERVAL_SECS}}"
    local lockfile="zed.zedlet.state.lock"
    local lockfile_fd=9
    local statefile="${ZED_RUNDIR}/zed.zedlet.state"
    local time_now
    local time_prev
    local umask_bak
    local rv=0

    [ -n "${tag}" ] || return 0

    zed_lock "${lockfile}" "${lockfile_fd}"
    time_now="$(date +%s)"
    time_prev="$(egrep "^[0-9]+;${tag}\$" "${statefile}" 2>/dev/null \
        | tail -1 | cut -d\; -f1)"

    if [ -n "${time_prev}" ] \
            && [ "$((time_now - time_prev))" -lt "${interval}" ]; then
        rv=1
    else
        umask_bak="$(umask)"
        umask 077
        egrep -v "^[0-9]+;${tag}\$" "${statefile}" 2>/dev/null \
            > "${statefile}.$$"
        echo "${time_now};${tag}" >> "${statefile}.$$"
        mv -f "${statefile}.$$" "${statefile}"
        umask "${umask_bak}"
    fi

    zed_unlock "${lockfile}" "${lockfile_fd}"
    return "${rv}"
}
