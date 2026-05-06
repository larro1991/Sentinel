# Wrap interactive login shells with script(1) so every keystroke and
# every byte of output is captured to /var/lib/sentry/logs/current/sessions/.
#
# Recursion guard: SENTRY_REC=1 is set inside the recorded shell, so the
# inner /etc/profile invocation skips the wrap.
#
# This file is sourced by /etc/profile for every login shell.

# Recording temporarily disabled — shell exits when exec script fails in PTY.
# TODO: re-enable after confirming script -c works in this Alpine/PTY context.
return 0 2>/dev/null || exit 0

# Don't wrap if:
#   - already inside a recorded session
#   - not interactive (cron, sftp-server subsystem, scp)
#   - log dir not yet ready (sentry-init didn't run, or pre-init shell)
#   - recording disabled by env var
if [ -n "$SENTRY_REC" ]; then
    return 0 2>/dev/null || exit 0
fi
case "$-" in *i*) ;; *) return 0 2>/dev/null || exit 0 ;; esac
[ -t 0 ] && [ -t 1 ] || return 0 2>/dev/null || exit 0
[ -d /var/lib/sentry/logs/current ] || return 0 2>/dev/null || exit 0
[ "${SENTRY_NO_REC:-0}" = "1" ] && return 0 2>/dev/null || exit 0

SENTRY_REC=1
export SENTRY_REC
SENTRY_LOG_DIR="/var/lib/sentry/logs/current/sessions"
export SENTRY_LOG_DIR
mkdir -p "$SENTRY_LOG_DIR" 2>/dev/null

_sentry_user=$(id -un)
_sentry_ts=$(date -u +%Y%m%dT%H%M%SZ)
_sentry_pid=$$
_sentry_remote="${SSH_CONNECTION:-local}"
_sentry_logbase="${SENTRY_LOG_DIR}/${_sentry_user}-${_sentry_ts}-${_sentry_pid}"

# Record connection metadata up front (in case session is brief).
{
    echo "session_start: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "user:          $_sentry_user"
    echo "tty:           $(tty 2>/dev/null || echo unknown)"
    echo "pid:           $_sentry_pid"
    echo "ssh_conn:      $_sentry_remote"
    echo "ssh_client:    ${SSH_CLIENT:-}"
    echo "ssh_tty:       ${SSH_TTY:-}"
    echo "auth_level:    $(cat /etc/sentry/auth.level 2>/dev/null || echo unknown)"
} > "${_sentry_logbase}.meta"

# Bash command-history with timestamps to its own file (parallel to typescript).
HISTFILE="${_sentry_logbase}.history"
HISTTIMEFORMAT='%F %T  '
HISTSIZE=10000
HISTFILESIZE=10000
export HISTFILE HISTTIMEFORMAT HISTSIZE HISTFILESIZE
PROMPT_COMMAND='history -a'
export PROMPT_COMMAND

# Hand control to script(1); when it exits, so does the login shell.
# If script is unavailable or the log dir isn't writable, fall through unrecorded.
if command -v script >/dev/null 2>&1 && touch "${_sentry_logbase}.typescript" 2>/dev/null; then
    exec script -q -f -c "${SHELL:-/bin/bash} -l" "${_sentry_logbase}.typescript"
else
    SENTRY_NO_REC=1
    export SENTRY_NO_REC
    exec "${SHELL:-/bin/bash}"
fi
