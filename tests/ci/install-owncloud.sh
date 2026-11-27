#!/bin/bash
# Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
# Original author: Marek Królikowski (TaKeN)
# Original project: https://github.com/takenek/impersonate
# SPDX-License-Identifier: AGPL-3.0-or-later
# See LICENSE and COPYRIGHT for the license and the AGPL section 7 attribution terms.
#
# Install a throw-away ownCloud (QA build: release + tests/ + PHPUnit) with SQLite and deploy this app
# into it. Used by CI (.github/workflows/ci.yml) and for local test runs. The tarball is verified by
# its SHA-256 (the value published next to the GitHub release asset of owncloud/core).
#
#   OC_DIR=/tmp/oc ADMIN_PASSWORD=... tests/ci/install-owncloud.sh
#
# Environment: OC_DIR (target, must not exist), ADMIN_PASSWORD (required), OC_VERSION / OC_SHA256
# (default: 11.1.0), APP_SRC (default: the repository root), APP_ARCHIVE (install this release archive
# into apps-external instead of the working tree), OC_TARBALL (use a local copy instead of
# downloading; still verified).
set -euo pipefail

OC_VERSION=${OC_VERSION:-11.1.0}
OC_SHA256=${OC_SHA256:-124424896d3049d79679f35dcaf0e349459fc807799f1ea46a6858bfaa2c192c}
APP_SRC=${APP_SRC:-$(cd "$(dirname "$0")/../.." && pwd)}
: "${OC_DIR:?set OC_DIR}"
: "${ADMIN_PASSWORD:?set ADMIN_PASSWORD}"

if [ -e "$OC_DIR" ]; then
	echo "$OC_DIR already exists" >&2
	exit 1
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

tarball=${OC_TARBALL:-$work/owncloud.tar.bz2}
if [ -z "${OC_TARBALL:-}" ]; then
	curl -sSfL -o "$tarball" \
		"https://github.com/owncloud/core/releases/download/v${OC_VERSION}/owncloud-${OC_VERSION}-qa.tar.bz2"
fi
echo "${OC_SHA256}  ${tarball}" | sha256sum --check --strict -

mkdir -p "$work/x"
tar -xjf "$tarball" -C "$work/x"
mkdir -p "$(dirname "$OC_DIR")"
mv "$work/x/owncloud" "$OC_DIR"

if [ -n "${APP_ARCHIVE:-}" ]; then
	# the release archive, installed the way README section 2 describes it
	mkdir -p "$OC_DIR/apps-external"
	tar -xzf "$APP_ARCHIVE" -C "$OC_DIR/apps-external"
	test -f "$OC_DIR/apps-external/impersonate/appinfo/info.xml"
else
	# the app: the built tree (compiled Handlebars templates), without VCS and local tooling
	test -f "$APP_SRC/js/templates/addImpersonateIcon.handlebars.js" \
		|| { echo "build the app first: make build-dep js-templates" >&2; exit 1; }
	mkdir -p "$OC_DIR/apps/impersonate"
	tar -C "$APP_SRC" \
		--exclude=./.git --exclude=./node_modules --exclude=./build \
		--exclude='./vendor-bin/*/vendor' --exclude=./tests/output --exclude=./tests/ui/node_modules \
		-cf - . | tar -C "$OC_DIR/apps/impersonate" -xf -
fi

occ() { php "$OC_DIR/occ" "$@"; }
occ maintenance:install --database sqlite --database-name owncloud \
	--admin-user admin --admin-pass "$ADMIN_PASSWORD" --data-dir "$OC_DIR/data" >/dev/null
occ config:system:set trusted_domains 0 --value=localhost >/dev/null
occ config:system:set trusted_domains 1 --value=127.0.0.1 >/dev/null
if [ -n "${APP_ARCHIVE:-}" ]; then
	php -r '
		$f = $argv[1]; $CONFIG = null; include $f;
		$CONFIG["apps_paths"] = [
			["path" => $argv[2] . "/apps", "url" => "/apps", "writable" => false],
			["path" => $argv[2] . "/apps-external", "url" => "/apps-external", "writable" => true],
		];
		file_put_contents($f, "<?php\n\$CONFIG = " . var_export($CONFIG, true) . ";\n");
	' "$OC_DIR/config/config.php" "$OC_DIR"
fi
# the app is not signed with an ownCloud certificate (README "Installation")
occ config:system:set integrity.ignore.missing.app.signature 0 --value=impersonate >/dev/null
occ app:enable impersonate
occ status
