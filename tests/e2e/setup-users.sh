#!/bin/bash
# Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
# Original author: Marek Królikowski (TaKeN)
# Original project: https://github.com/takenek/impersonate
# SPDX-License-Identifier: AGPL-3.0-or-later
# See LICENSE and COPYRIGHT for the license and the AGPL section 7 attribution terms.
#
# Create the users and groups the HTTP end-to-end tests expect:
#   admin (admin), dave (member of "admin"), alice (g1), bob (g2), carol (g1, group admin of g1)
# and log every user in once (impersonation needs a previous login).
. "$(dirname "$0")/lib.sh"
trap 'rm -rf "$W"' EXIT
occ config:system:set allow_subadmins --value=true --type=boolean >/dev/null
for g in g1 g2; do occ group:add "$g" >/dev/null 2>&1 || true; done
for u in alice bob carol dave; do
	occ OC_PASS="$USER_PASSWORD" user:add --password-from-env "$u" >/dev/null 2>&1 || true
done
occ group:add-member g1 -m alice -m carol >/dev/null
occ group:add-member g2 -m bob >/dev/null
occ group:add-member admin -m dave >/dev/null
ocs_admin -X POST "$BASE/ocs/v1.php/cloud/users/carol/subadmins" -d groupid=g1 >/dev/null
for u in alice bob carol dave; do login "$W/$u" "$u" "$USER_PASSWORD"; check "$(whoami_ "$W/$u")" "$u" "first login of $u"; done
check "$(ocs_admin "$BASE/ocs/v1.php/cloud/users/carol/subadmins?format=json" | php -r '$j = json_decode(stream_get_contents(STDIN), true); echo implode(",", $j["ocs"]["data"] ?? []);')" g1 "carol is group admin of g1"
reset_policy
finish
