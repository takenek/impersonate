#!/bin/bash
# Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
# Original author: Marek Królikowski (TaKeN)
# Original project: https://github.com/takenek/impersonate
# SPDX-License-Identifier: AGPL-3.0-or-later
# See LICENSE and COPYRIGHT for the license and the AGPL section 7 attribution terms.
#
# HTTP end-to-end test of the impersonate app: impersonation by admins and group admins, switching
# back by logging out, CSRF, refusals, ownCloud 11's allow_subadmins switch.
# Expects the users of setup-users.sh. Environment: see lib.sh.
. "$(dirname "$0")/lib.sh"
trap 'rm -rf "$W"; reset_policy; occ config:system:set allow_subadmins --value=true --type=boolean >/dev/null' EXIT
reset_policy
occ config:system:set allow_subadmins --value=true --type=boolean >/dev/null
A="$W/admin"; B="$W/bob"; C="$W/carol"

echo "== admin impersonates alice and returns via logout"
login "$A" admin "$ADMIN_PASSWORD"
check "$(whoami_ "$A")" admin "admin logged in"
data=$(curl -s -b "$A" -H "requesttoken: $(token "$A")" "$BASE/index.php/apps/impersonate/getimpersonatedata"); echo "  getimpersonatedata (admin): $data"
check "$(echo "$data" | php -r '$j=json_decode(stream_get_contents(STDIN),true); echo is_array($j) ? "json" : "not-json";')" json "getimpersonatedata returns JSON"
page=$(curl -s -b "$A" "$BASE/index.php/settings/users")
echo "$page" | command grep -q 'impersonate/js/impersonate.js' && ok "users page loads impersonate.js" || bad "users page does not load impersonate.js"
echo "$page" | command grep -q 'addImpersonateIcon.handlebars.js' && ok "users page loads handlebars template" || bad "users page does not load handlebars template"
code=$(imp "$A" alice); check "$code" 200 "POST impersonate alice"
check "$(whoami_ "$A")" alice "session is now alice"
home=$(curl -s -b "$A" "$BASE/index.php/apps/files/")
echo "$home" | command grep -q 'impersonate_logout.js' && ok "impersonation banner script loaded" || bad "impersonation banner script NOT loaded"
code=$(imp "$A" bob); check "$code" 404 "nested impersonation refused"
app_body "$W/body" stopNestedImpersonation "nested -> stopNestedImpersonation"
code=$(logout "$A"); echo "  logout HTTP $code"
check "$(whoami_ "$A")" admin "logout returned to admin"
code=$(logout "$A"); echo "  second logout HTTP $code"
check "$(whoami_ "$A")" anonymous "second logout really logs out"

echo "== negative cases"
login "$A" admin "$ADMIN_PASSWORD"
code=$(imp "$A" nosuchuser); check "$code" 404 "unknown user refused"
login "$B" bob "$USER_PASSWORD"
code=$(imp "$B" alice); check "$code" 404 "normal user cannot impersonate"
check "$(whoami_ "$B")" bob "bob is still bob"
code=$(imp "$B" admin); check "$code" 404 "normal user cannot impersonate admin"
login "$C" carol "$USER_PASSWORD"
code=$(imp "$C" admin); check "$code" 404 "subadmin cannot impersonate admin"
code=$(imp "$C" alice); check "$code" 404 "subadmin cannot impersonate when only admins allowed"
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$A" -X POST "$BASE/index.php/apps/impersonate/user" --data-urlencode target=alice); check "$code" 412 "POST without CSRF token rejected"

echo "== group admin modes"
setcfg impersonate_all_groupadmins true
login "$C" carol "$USER_PASSWORD"
code=$(imp "$C" bob); check "$code" 404 "all-groupadmins: carol cannot impersonate bob (g2)"
code=$(imp "$C" alice); check "$code" 200 "all-groupadmins: carol impersonates alice (g1)"
check "$(whoami_ "$C")" alice "carol session is alice"
logout "$C" >/dev/null; check "$(whoami_ "$C")" carol "carol returned"
setcfg impersonate_all_groupadmins false; setcfg impersonate_include_groups true; setcfg impersonate_include_groups_list '["g1"]'
login "$C" carol "$USER_PASSWORD"
code=$(imp "$C" alice); check "$code" 200 "include-groups [g1]: carol impersonates alice"
logout "$C" >/dev/null; check "$(whoami_ "$C")" carol "carol returned"
code=$(imp "$C" bob); check "$code" 404 "include-groups [g1]: carol cannot impersonate bob"
setcfg impersonate_include_groups false; setcfg impersonate_include_groups_list '[]'

echo "== allow_subadmins=false (OC 11 default) disables group-admin impersonation"
setcfg impersonate_all_groupadmins true
occ config:system:set allow_subadmins --value=false --type=boolean >/dev/null
login "$C" carol "$USER_PASSWORD"
code=$(imp "$C" alice); check "$code" 404 "subadmin feature off: carol cannot impersonate alice"
check "$(whoami_ "$C")" carol "carol is still carol"
setcfg impersonate_all_groupadmins false
occ config:system:set allow_subadmins --value=true --type=boolean >/dev/null

finish
