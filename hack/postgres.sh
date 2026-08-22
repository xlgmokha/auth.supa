#!/usr/bin/env bash
#
# Runs a PostgreSQL cluster for development and tests, without Docker.
#
# The cluster is self contained: its data lives in .postgres/ inside the repo,
# starting it touches no system wide PostgreSQL install, and "stop" leaves
# nothing behind. If a server is already listening on $PGPORT -- your own
# PostgreSQL, or the one from docker-compose-dev.yml -- that server is used as
# is and these commands do nothing to it.
#
# Usage: hack/postgres.sh {start|stop|status|bindir}

set -euo pipefail

cd "$(dirname "$0")/.."

PGHOST="${PGHOST:-127.0.0.1}"
PGPORT="${PGPORT:-5432}"
PGDATA_DIR="${PGDATA_DIR:-.postgres}"

die() {
	echo "postgres.sh: $*" >&2
	exit 1
}

# The server binaries (initdb, pg_ctl) are not on PATH on Debian and Ubuntu,
# and Homebrew only puts them there while the formula is linked. Look in the
# usual places and take the newest version found.
find_bindir() {
	if [ -n "${PG_BIN:-}" ]; then
		[ -x "$PG_BIN/pg_ctl" ] || die "PG_BIN=$PG_BIN does not contain pg_ctl"
		echo "$PG_BIN"
		return
	fi

	if command -v pg_ctl >/dev/null 2>&1; then
		dirname "$(command -v pg_ctl)"
		return
	fi

	local found="" dir
	for dir in /usr/lib/postgresql/*/bin \
		/opt/homebrew/opt/postgresql@*/bin \
		/usr/local/opt/postgresql@*/bin; do
		if [ -x "$dir/pg_ctl" ]; then
			found="$found$dir"$'\n'
		fi
	done
	found="$(printf '%s' "$found" | sort -V | tail -n 1)"

	[ -n "$found" ] || die "could not find PostgreSQL.
  macOS:         brew install postgresql@15
  Debian/Ubuntu: apt-get install postgresql
Or set PG_BIN to the directory containing pg_ctl."

	echo "$found"
}

BINDIR="$(find_bindir)"

# initdb and pg_ctl refuse to run as root. Container based dev environments
# usually are root, so drop down to the "postgres" system user that the
# PostgreSQL packages create for exactly this purpose.
RUNAS=""
if [ "$(id -u)" -eq 0 ]; then
	id postgres >/dev/null 2>&1 ||
		die "running as root and there is no 'postgres' user to drop down to. Re-run as a non-root user."
	RUNAS=postgres
fi

as_postgres() {
	if [ -n "$RUNAS" ]; then
		su "$RUNAS" -s /bin/sh -c "$(printf '%q ' "$@")"
	else
		"$@"
	fi
}

# Is anything at all serving on the port we care about?
server_listening() {
	"$BINDIR/pg_isready" -h "$PGHOST" -p "$PGPORT" -q
}

# Is the cluster in $PGDATA_DIR -- the one we manage -- the thing running?
ours_running() {
	[ -f "$PGDATA_DIR/PG_VERSION" ] || return 1
	as_postgres "$BINDIR/pg_ctl" -D "$PGDATA_DIR" status >/dev/null 2>&1
}

cmd_start() {
	if server_listening; then
		echo "PostgreSQL already accepting connections on $PGHOST:$PGPORT, using it."
		return 0
	fi

	if [ ! -f "$PGDATA_DIR/PG_VERSION" ]; then
		echo "Initialising a new PostgreSQL cluster in $PGDATA_DIR"
		mkdir -p "$PGDATA_DIR"
		if [ -n "$RUNAS" ]; then
			chown -R "$RUNAS" "$PGDATA_DIR"
		fi
		as_postgres "$BINDIR/initdb" \
			-D "$PGDATA_DIR" -U postgres --auth=trust --encoding=UTF8 >/dev/null
	fi

	echo "Starting PostgreSQL on $PGHOST:$PGPORT"
	as_postgres "$BINDIR/pg_ctl" \
		-D "$PGDATA_DIR" -l "$PGDATA_DIR/server.log" -o "-p $PGPORT -k /tmp" -w start
}

cmd_stop() {
	if [ ! -f "$PGDATA_DIR/PG_VERSION" ]; then
		echo "No cluster in $PGDATA_DIR, nothing to stop."
		return 0
	fi

	if ! ours_running; then
		if server_listening; then
			echo "$PGHOST:$PGPORT is served by something we did not start, leaving it alone."
		else
			echo "Cluster in $PGDATA_DIR is not running."
		fi
		return 0
	fi

	echo "Stopping PostgreSQL in $PGDATA_DIR"
	as_postgres "$BINDIR/pg_ctl" -D "$PGDATA_DIR" -m fast -w stop
}

cmd_status() {
	if ours_running; then
		echo "running: cluster in $PGDATA_DIR on $PGHOST:$PGPORT"
	elif server_listening; then
		echo "running: a PostgreSQL we did not start, on $PGHOST:$PGPORT"
	else
		echo "stopped: nothing listening on $PGHOST:$PGPORT"
	fi
}

case "${1:-}" in
start) cmd_start ;;
stop) cmd_stop ;;
status) cmd_status ;;
bindir) echo "$BINDIR" ;;
*) die "usage: hack/postgres.sh {start|stop|status|bindir}" ;;
esac
