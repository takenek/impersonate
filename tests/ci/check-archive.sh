#!/bin/bash
# Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
# Original author: Marek Królikowski (TaKeN)
# Original project: https://github.com/takenek/impersonate
# SPDX-License-Identifier: AGPL-3.0-or-later
# See LICENSE and COPYRIGHT for the license and the AGPL section 7 attribution terms.
#
# The release archive holds the app and nothing else: every member must match the allow-list
# below (one folder "impersonate", required by the ownCloud 11 installer), be a regular file with
# the mode 644 or 755 or a directory with the mode 755 (no symbolic or hard link, no device, no
# set-uid/set-gid/sticky bit, nothing writable by group or others), appear once and belong to 0/0;
# the compiled templates must be there and the version must be the expected one.
#
#   tests/ci/check-archive.sh build/impersonate-1.0.4.tar.gz 1.0.4
set -euo pipefail
archive=${1:?archive}
version=${2:?version}
allowed='^impersonate/((AUTHORS\.md|CHANGELOG\.md|COPYRIGHT|LICENSE|README\.md|SECURITY\.md)|appinfo/(app\.php|info\.xml|register_command\.php|routes\.php)|controller/[a-z]+\.php|css/[a-z-]+\.css|img/[a-z0-9_-]+\.svg|js/[a-z_-]+\.js|js/templates/[A-Za-z]+\.handlebars\.js|l10n/[A-Za-z0-9_@-]+\.(js|json)|lib/([A-Za-z]+/)?[A-Za-z]+\.php|templates/[a-z-]+\.php|([A-Za-z0-9_]+/)*)$'
bad=0
while IFS= read -r member; do
	if ! [[ "$member" =~ $allowed ]]; then
		echo "not allowed in the release archive: $member" >&2
		bad=1
	fi
done < <(tar -tzf "$archive")
# README.md refers to SECURITY.md: the archive carries the document of its own version; the
# translations include locale codes with digits, "@" and "-" (es_419, sr@latin, zh-Hans)
for required in impersonate/appinfo/info.xml impersonate/COPYRIGHT impersonate/LICENSE \
	impersonate/README.md impersonate/SECURITY.md impersonate/appinfo/register_command.php \
	impersonate/lib/BackgroundJob/Reconcile.php impersonate/lib/Command/Active.php \
	impersonate/js/templates/addImpersonateIcon.handlebars.js \
	impersonate/js/templates/removeImpersonateIcon.handlebars.js \
	impersonate/js/templates/impersonateNotification.handlebars.js \
	impersonate/l10n/pl.js impersonate/l10n/pl.json impersonate/l10n/es_419.js impersonate/l10n/sr@latin.js \
	impersonate/l10n/zh-Hans.js; do
	tar -tzf "$archive" "$required" >/dev/null 2>&1 || { echo "missing in the release archive: $required" >&2; bad=1; }
done
# (each check reads all of its input itself: a reader that stops early, like grep -q, would end
# the pipeline with SIGPIPE, which pipefail turns into "no match")
info=$(tar -xzOf "$archive" impersonate/appinfo/info.xml || true)
[[ "$info" == *"<version>${version}</version>"* ]] \
	|| { echo "info.xml in the archive does not have version $version" >&2; bad=1; }
listing=$(LC_ALL=C tar --numeric-owner -tzvf "$archive")
# type and mode: a link ("l", "h"), a device, a special bit (s, S, t, T) or any other mode does not match
if ! awk '$1 !~ /^(-rw-r--r--|-rwxr-xr-x|drwxr-xr-x)$/ { print > "/dev/stderr"; found = 1 } END { exit found }' <<<"$listing"; then
	echo "archive members must be regular files with the mode 644 or 755 or directories with the mode 755" >&2
	bad=1
fi
if ! awk '$2 != "0/0" { print > "/dev/stderr"; found = 1 } END { exit found }' <<<"$listing"; then
	echo "archive members must be owned by 0/0" >&2
	bad=1
fi
# every path once (tar would extract a later member over an earlier one of the same name)
duplicates=$(tar -tzf "$archive" | sed 's:/$::' | LC_ALL=C sort | uniq -d)
if [ -n "$duplicates" ]; then
	echo "names that appear more than once in the release archive: $duplicates" >&2
	bad=1
fi
[ "$bad" -eq 0 ] && echo "release archive OK: $(tar -tzf "$archive" | wc -l) members"
exit "$bad"
