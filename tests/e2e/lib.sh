#!/bin/bash
# Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
# Original author: Marek Królikowski (TaKeN)
# Original project: https://github.com/takenek/impersonate
# SPDX-License-Identifier: AGPL-3.0-or-later
# See LICENSE and COPYRIGHT for the license and the AGPL section 7 attribution terms.
#
# Shared helpers of the HTTP end-to-end tests (sourced by e2e.sh, security-checks.sh, setup-users.sh).
#
# Environment:
#   OC_DIR          ownCloud directory (required)
#   ADMIN_PASSWORD  password of the user "admin" (required)
#   USER_PASSWORD   password of the test users alice, bob, carol, dave (required)
#   BASE            URL of the instance (default http://localhost:8080)
#   PHP_AS          prefix that runs a command as the web server user, e.g. "sudo -u www-data"
#                   (default: none, i.e. the current user owns the instance)
#   SESSION_DIR     PHP session directory of the web server (default: session.save_path or the temp dir)
#   CONFIG_DELAY    seconds to wait after "occ config:system:set" (opcache revalidation; default 3)
#   ERROR_PAGES_REPLACED  1 if the web server replaces the error pages of ownCloud (nginx with
#                   fastcgi_intercept_errors, as the ownCloud documentation configures it): the body
#                   of a refusal is then the web server's page, only its status comes from the app
#
# The database of the instance is read as config.php describes it (SQLite, MySQL/MariaDB or
# PostgreSQL; the PHP extension pdo_sqlite, pdo_mysql or pdo_pgsql is needed).
set -uo pipefail

: "${OC_DIR:?set OC_DIR}"
: "${ADMIN_PASSWORD:?set ADMIN_PASSWORD}"
: "${USER_PASSWORD:?set USER_PASSWORD}"
BASE=${BASE:-http://localhost:8080}
PHP_AS=${PHP_AS:-}
CONFIG_DELAY=${CONFIG_DELAY:-3}
E2E_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [ -z "${SESSION_DIR:-}" ]; then
	SESSION_DIR=$(php -r '$p = (string)session_save_path(); $p = substr($p, (int)strrpos(";" . $p, ";")); echo $p !== "" ? $p : sys_get_temp_dir();')
fi
W=$(mktemp -d)
PASS=0
FAIL=0

ok() { echo "  PASS: $*"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $*"; FAIL=$((FAIL + 1)); }
check() { if [ "$1" = "$2" ]; then ok "$3 ($1)"; else bad "$3 (expected '$2', got '$1')"; fi; }
finish() { echo "== result: $PASS passed, $FAIL failed"; [ "$FAIL" -eq 0 ]; }

# occ [VAR=value ...] <command> [args]: run occ as the web server user (with environment variables)
occ() {
	local envs=()
	while [ $# -gt 0 ] && [[ "$1" == [A-Z_]*=* ]]; do
		envs+=("$1")
		shift
	done
	# shellcheck disable=SC2086
	$PHP_AS env "${envs[@]}" php "$OC_DIR/occ" "$@"
	local rc=$?
	case "${1:-}" in config:system:*) sleep "$CONFIG_DELAY" ;; esac
	return $rc
}
# DB_PHP: PHP code that connects $pdo to the database of the instance as config.php describes it
# (argv[1] = OC_DIR, argv[3] = "ro" for a read-only SQLite connection); sql and sqlx run it as the web
# server user ($PHP_AS), like occ, because config.php is readable only by that user. Identifiers in
# double quotes (e.g. "user") and a backslash in a string literal mean the same on all three
# databases (MySQL: ANSI_QUOTES, NO_BACKSLASH_ESCAPES); a SQLite connection waits up to 15 s while
# the web server holds a lock.
DB_PHP='
	$CONFIG = [];
	if (!(@include $argv[1] . "/config/config.php") || !isset($CONFIG["dbtype"])) {
		fwrite(STDERR, "cannot read the database settings in " . $argv[1] . "/config/config.php (PHP_AS?)\n");
		exit(1);
	}
	$type = $CONFIG["dbtype"];
	// "host", "host:port" or "host:/path/to/socket", as ownCloud reads dbhost
	$host = (string)($CONFIG["dbhost"] ?? "localhost");
	$port = null;
	$socket = null;
	if (($p = strpos($host, ":", 1)) !== false) {
		$rest = substr($host, $p + 1);
		$host = substr($host, 0, $p);
		if (ctype_digit($rest)) { $port = $rest; } else { $socket = $rest; }
	}
	if ($type === "sqlite" || $type === "sqlite3") {
		$file = rtrim((string)($CONFIG["datadirectory"] ?? $argv[1] . "/data"), "/") . "/" . ($CONFIG["dbname"] ?? "owncloud") . ".db";
		$opts = [PDO::ATTR_TIMEOUT => 15];
		if (($argv[3] ?? "") === "ro") { $opts[PDO::SQLITE_ATTR_OPEN_FLAGS] = PDO::SQLITE_OPEN_READONLY; }
		$pdo = new PDO("sqlite:" . $file, null, null, $opts);
	} elseif ($type === "mysql") {
		$pdo = new PDO("mysql:" . ($socket !== null ? "unix_socket=$socket" : "host=$host" . ($port ? ";port=$port" : "")) . ";dbname=" . $CONFIG["dbname"] . ";charset=utf8mb4", $CONFIG["dbuser"], $CONFIG["dbpassword"]);
		$pdo->exec("SET SESSION sql_mode = CONCAT(@@sql_mode, \",ANSI_QUOTES,NO_BACKSLASH_ESCAPES\")");
	} elseif ($type === "pgsql") {
		$pdo = new PDO("pgsql:host=" . ($socket ?? $host) . ($port ? ";port=$port" : "") . ";dbname=" . $CONFIG["dbname"], $CONFIG["dbuser"], $CONFIG["dbpassword"]);
	} else {
		fwrite(STDERR, "unsupported database type $type\n");
		exit(1);
	}
	$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
'
# sql <query>: first column of the first row
sql() {
	# shellcheck disable=SC2016,SC2086
	$PHP_AS php -r "$DB_PHP"'
		try {
			$r = $pdo->query($argv[2])->fetchColumn();
		} catch (Throwable $e) {
			fwrite(STDERR, "sql: query failed: " . $e->getMessage() . "\n");
			exit(1);
		}
		echo $r === false || $r === null ? "" : $r;
	' "$OC_DIR" "$1" ro
}
# sqlx <statement>: change the test database directly (fixtures the web interface can not produce)
sqlx() {
	# shellcheck disable=SC2016,SC2086
	$PHP_AS php -r "$DB_PHP"'
		try {
			$pdo->exec($argv[2]);
		} catch (Throwable $e) {
			fwrite(STDERR, "sqlx: statement failed: " . $e->getMessage() . "\n");
			exit(1);
		}
	' "$OC_DIR" "$1" rw
}
# app_body <file> <text> <what>: the body of a refusal names the reason. With ERROR_PAGES_REPLACED=1
# an HTML error page of the web server counts as well (the status is checked separately).
app_body() {
	if command grep -q -- "$2" "$1"; then
		ok "$3"
	elif [ "${ERROR_PAGES_REPLACED:-0}" = 1 ] && command grep -qi '<!DOCTYPE html' "$1"; then
		ok "$3 (the web server replaced the error page)"
	else
		bad "$3: $(head -c 400 "$1")"
	fi
}
setcfg() { occ config:app:set impersonate "$1" --value="$2" >/dev/null; }
reset_policy() {
	setcfg impersonate_all_groupadmins false
	setcfg impersonate_include_groups false
	setcfg impersonate_include_groups_list '[]'
	setcfg impersonate_allow_groupadmin_targets false
}
# active_records: number of impersonations the server knows to be active (ActiveImpersonations)
active_records() { sql "select count(*) from oc_appconfig where appid='impersonate' and configkey like 'active!_%' escape '!'"; }
# log_count <text>: number of ownCloud log entries of the app whose message contains the text
log_count() {
	# shellcheck disable=SC2086
	$PHP_AS cat "$OC_DIR/data/owncloud.log" 2>/dev/null | php -r '
		$n = 0;
		while (($line = fgets(STDIN)) !== false) {
			$entry = json_decode($line, true);
			if (is_array($entry) && ($entry["app"] ?? "") === "impersonate" && is_string($entry["message"] ?? null)
				&& strpos($entry["message"], $argv[1]) !== false) {
				$n++;
			}
		}
		echo $n;
	' "$1"
}
COOKIE=$(occ config:system:get instanceid)

# login <jar> <user> <password>
login() {
	local tok
	rm -f "$1"
	tok=$(curl -s -c "$1" -b "$1" "$BASE/index.php/login" | command grep -o 'data-requesttoken="[^"]*"' | head -1 | cut -d'"' -f2)
	curl -s -o /dev/null -c "$1" -b "$1" -X POST "$BASE/index.php/login" \
		--data-urlencode "user=$2" --data-urlencode "password=$3" --data-urlencode "requesttoken=$tok" \
		-d timezone=UTC -d timezone-offset=0
}
# token <jar>: CSRF token of the session
token() { curl -s -c "$1" -b "$1" "$BASE/index.php/apps/files/" | command grep -o 'data-requesttoken="[^"]*"' | head -1 | cut -d'"' -f2; }
# whoami_ <jar>: uid of the session or "anonymous"
whoami_() {
	curl -s -c "$1" -b "$1" -H 'OCS-APIREQUEST: true' "$BASE/ocs/v1.php/cloud/user?format=json" \
		| php -r '$j = json_decode(stream_get_contents(STDIN), true); echo $j["ocs"]["data"]["id"] ?? "anonymous";'
}
# imp <jar> <target>: HTTP status of the impersonation request, body in $W/body
imp() {
	local t
	t=$(token "$1")
	curl -s -o "$W/body" -w '%{http_code}' -c "$1" -b "$1" -H "requesttoken: $t" \
		-X POST "$BASE/index.php/apps/impersonate/user" --data-urlencode "target=$2"
}
# logout <jar>: the user clicks "Log out"
logout() {
	local t
	t=$(token "$1")
	curl -s -o /dev/null -w '%{http_code}' -c "$1" -b "$1" \
		"$BASE/index.php/logout?requesttoken=$(php -r 'echo rawurlencode($argv[1]);' "$t")"
}
ocs_admin() { curl -s -u "admin:$ADMIN_PASSWORD" -H 'OCS-APIREQUEST: true' "$@"; }
sid() { awk -F'\t' -v c="$COOKIE" '$6 == c {print $7}' "$1" | tail -1; }
# rawsid <jar>: the session id of the jar as the server knows it (not URL encoded)
rawsid() { php -r 'echo urldecode($argv[1]);' "$(sid "$1")"; }
# sess <jar>: decrypted session of the jar (passwords masked)
sess() {
	local pp
	pp=$(awk -F'\t' '$6 == "oc_sessionPassphrase" {print $7}' "$1" | tail -1)
	pp=$(php -r 'echo urldecode($argv[1]);' "$pp")
	# shellcheck disable=SC2086
	$PHP_AS env OC_DIR="$OC_DIR" SESSION_DIR="$SESSION_DIR" KNOWN_PW="admin=$ADMIN_PASSWORD;testuser=$USER_PASSWORD" \
		php /dev/stdin "$(sid "$1")" "$pp" < "$E2E_DIR/dumpsess.php" 2>/dev/null
}
