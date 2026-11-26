#!/bin/bash
# Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
# Original author: Marek Królikowski (TaKeN)
# Original project: https://github.com/takenek/impersonate
# SPDX-License-Identifier: AGPL-3.0-or-later
# See LICENSE and COPYRIGHT for the license and the AGPL section 7 attribution terms.
#
# The release archive holds the app and nothing else: every member must match the allow-list
# below (one folder "impersonate", required by the ownCloud 11 installer), the compiled templates
# must be there and the version must be the expected one.
#
#   tests/ci/check-archive.sh build/impersonate-1.0.0.tar.gz 1.0.0
set -euo pipefail
archive=${1:?archive}
version=${2:?version}
allowed='^impersonate/((AUTHORS\.md|CHANGELOG\.md|COPYRIGHT|LICENSE|README\.md)|appinfo/(app\.php|info\.xml|routes\.php)|controller/[a-z]+\.php|css/[a-z-]+\.css|img/[a-z0-9_-]+\.svg|js/[a-z_-]+\.js|js/templates/[A-Za-z]+\.handlebars\.js|l10n/[A-Za-z_@]+\.(js|json)|lib/([A-Za-z]+/)?[A-Za-z]+\.php|templates/[a-z-]+\.php|([A-Za-z0-9_]+/)*)$'
bad=0
while IFS= read -r member; do
	if ! [[ "$member" =~ $allowed ]]; then
		echo "not allowed in the release archive: $member" >&2
		bad=1
	fi
done < <(tar -tzf "$archive")
for required in impersonate/appinfo/info.xml impersonate/COPYRIGHT impersonate/LICENSE \
	impersonate/js/templates/addImpersonateIcon.handlebars.js \
	impersonate/js/templates/removeImpersonateIcon.handlebars.js \
	impersonate/js/templates/impersonateNotification.handlebars.js; do
	tar -tzf "$archive" "$required" >/dev/null 2>&1 || { echo "missing in the release archive: $required" >&2; bad=1; }
done
tar -xzOf "$archive" impersonate/appinfo/info.xml | grep -q "<version>${version}</version>" \
	|| { echo "info.xml in the archive does not have version $version" >&2; bad=1; }
if tar -tzvf "$archive" | awk '{print $2}' | grep -qv '^0/0$'; then
	echo "archive members must be owned by 0/0" >&2
	bad=1
fi
[ "$bad" -eq 0 ] && echo "release archive OK: $(tar -tzf "$archive" | wc -l) members"
exit "$bad"
