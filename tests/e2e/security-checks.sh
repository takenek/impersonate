#!/bin/bash
# Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
# Original author: Marek Królikowski (TaKeN)
# Original project: https://github.com/takenek/impersonate
# SPDX-License-Identifier: AGPL-3.0-or-later
# See LICENSE and COPYRIGHT for the license and the AGPL section 7 attribution terms.
#
# Live checks of the security properties of the impersonate app (see SECURITY.md):
# session isolation, session id / CSRF rotation, password-bound token after switching back, refused
# credential minting, per-request re-validation, invalid targets, removed routes, policy disclosure,
# malformed configuration, concurrent requests during the switch.
# Expects the users of setup-users.sh. Environment: see lib.sh. Uses only throw-away rv* accounts.
. "$(dirname "$0")/lib.sh"
restore() {
	reset_policy
	for u in alice bob carol dave; do occ user:enable "$u" >/dev/null 2>&1; done
	occ group:remove-member g1 -m dave >/dev/null 2>&1
	occ user:delete rvadmin >/dev/null 2>&1
	occ config:app:delete core last_check_timeout >/dev/null 2>&1
	occ config:system:set allow_subadmins --value=true --type=boolean >/dev/null
}
trap 'rm -rf "$W"; restore' EXIT
restore
A=$W/admin; Bj=$W/bob; C=$W/carol
MARK=$(sql "select coalesce(max(id),0) from oc_authtoken")
sessfile() { $PHP_AS cat "$SESSION_DIR/sess_$1" 2>/dev/null; }

echo "== A. session isolation, id + CSRF rotation, password-bound token after return"
login "$A" admin "$ADMIN_PASSWORD"
S1=$(sid "$A"); T1=$(token "$A")
sess "$A" > "$W/s1"
command grep -q '"uid":"admin"' "$W/s1" && ok "admin session holds its session credentials before" || bad "no credentials blob in the admin session (cannot test isolation)"
check "$(imp "$A" alice)" 200 "admin impersonates alice"
S2=$(sid "$A"); T2=$(token "$A")
[ "$S1" != "$S2" ] && ok "session id rotated on start" || bad "session id not rotated on start"
sessfile "$S1" | command grep -q encrypted_session_data && bad "old session id still holds session data" || ok "old session id holds no authenticated state"
[ "$T1" != "$T2" ] && ok "CSRF token rotated on start" || bad "CSRF token not rotated on start"
sess "$A" > "$W/s2"
command grep -q '^  password::sessioncredentials/credentials =>' "$W/s2" && bad "impersonator credentials active in the impersonated session" || ok "impersonator credentials not active in the impersonated session"
check "$(command grep -o '  loginname => "[^"]*"' "$W/s2" | cut -d'"' -f2)" alice "loginname is the target during impersonation"
check "$(sql "select count(*) from oc_authtoken where id>$MARK and uid='alice' and name='Impersonated by admin'")" 1 "target token named 'Impersonated by admin'"
check "$(sql "select count(*) from oc_authtoken where id>$MARK and uid='admin' and type=0 and password is not null")" 1 "admin's parked token keeps the password"

echo "== B. no lasting credentials can be obtained while impersonating"
BEFORE=$(sql "select count(*) from oc_authtoken where uid='alice' and type=1")
for path in /index.php/settings/personal/authtokens /index.php//settings/personal/authtokens /index.php/settings/personal/authtoken%73; do
	code=$(curl -s -o /dev/null -w '%{http_code}' -b "$A" -c "$A" -H "requesttoken: $(token "$A")" -X POST "$BASE$path" -d name=evil)
	case "$code" in 403|404) ok "POST $path refused ($code)" ;; *) bad "POST $path -> $code" ;; esac
done
check "$(sql "select count(*) from oc_authtoken where uid='alice' and type=1")" "$BEFORE" "no app password created for alice"
for v in v1 v2; do
	code=$(curl -s -o /dev/null -w '%{http_code}' -b "$A" -c "$A" -H 'OCS-APIREQUEST: true' "$BASE/ocs/$v.php/cloud/user/signing-key?format=json")
	check "$code" 403 "GET /ocs/$v.php/cloud/user/signing-key refused"
done
check "$(sql "select count(*) from oc_preferences where userid='alice' and configkey='signing-key'")" 0 "no URL signing key created for alice"
check "$(whoami_ "$A")" alice "still impersonating after the refused requests"
logout "$A" >/dev/null
S3=$(sid "$A"); T3=$(token "$A")
check "$(whoami_ "$A")" admin "logout returns to admin"
[ "$S3" != "$S2" ] && ok "session id rotated on return" || bad "session id not rotated on return"
[ "$T3" != "$T2" ] && ok "CSRF token rotated on return" || bad "CSRF token not rotated on return"
sess "$A" > "$W/s3"
command grep -q '"uid":"admin"' "$W/s3" && ok "admin session credentials restored" || bad "admin session credentials not restored"
command grep -q 'impersonat' "$W/s3" && bad "impersonation keys left in the session" || ok "no impersonation keys left"
check "$(sql "select count(*) from oc_authtoken where id>$MARK and uid='admin' and type=0 and password is null")" 0 "admin's restored session token is password-bound"
check "$(sql "select count(*) from oc_authtoken where id>$MARK and uid='admin' and type=0")" 1 "exactly one admin session token (parked token removed)"
check "$(sql "select count(*) from oc_authtoken where id>$MARK and name='Impersonated by admin'")" 0 "impersonation token removed"

echo "== C. impersonation is re-validated on every request"
setcfg impersonate_all_groupadmins true
login "$C" carol "$USER_PASSWORD"
check "$(imp "$C" alice)" 200 "carol impersonates alice"
occ user:disable carol >/dev/null
check "$(whoami_ "$C")" anonymous "impersonator disabled -> session ends"
occ user:enable carol >/dev/null
login "$C" carol "$USER_PASSWORD"; check "$(imp "$C" alice)" 200 "carol impersonates alice again"
setcfg impersonate_all_groupadmins false
check "$(whoami_ "$C")" anonymous "permission revoked -> session ends"
setcfg impersonate_all_groupadmins true
login "$A" admin "$ADMIN_PASSWORD"; check "$(imp "$A" bob)" 200 "admin impersonates bob"
TID=$(sql "select id from oc_authtoken where uid='bob' and name='Impersonated by admin' order by id desc limit 1")
[ -n "$TID" ] || bad "impersonation token of bob not found"
login "$Bj" bob "$USER_PASSWORD"
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$Bj" -c "$Bj" -H "requesttoken: $(token "$Bj")" -X DELETE "$BASE/index.php/settings/personal/authtokens/$TID")
check "$code" 200 "bob revokes the 'Impersonated by admin' session"
curl -s -o /dev/null -b "$A" -c "$A" "$BASE/index.php/logout"
check "$(whoami_ "$A")" anonymous "revoked session + GET /logout without CSRF token -> logged out (no switch back)"
login "$A" admin "$ADMIN_PASSWORD"; check "$(imp "$A" bob)" 200 "admin impersonates bob again"
PID=$(sql "select id from oc_authtoken where uid='admin' and type=0 order by id desc limit 1")
[ -n "$PID" ] || bad "parked admin token not found"
occ_admin_revoke() { curl -s -o /dev/null -w '%{http_code}' -b "$1" -c "$1" -H "requesttoken: $(token "$1")" -X DELETE "$BASE/index.php/settings/personal/authtokens/$2"; }
A2=$W/admin2; login "$A2" admin "$ADMIN_PASSWORD"
check "$(occ_admin_revoke "$A2" "$PID")" 200 "admin revokes the parked session from another browser"
check "$(whoami_ "$A")" anonymous "revoked impersonator session -> impersonation ends"
# impersonator password change (core re-checks passwords every last_check_timeout minutes)
occ config:app:set core last_check_timeout --value=0 >/dev/null
RV_PW="Rv-$(php -r 'echo bin2hex(random_bytes(6));')"
occ OC_PASS="$RV_PW" user:add --password-from-env --group=admin rvadmin >/dev/null
R=$W/rvadmin; login "$R" rvadmin "$RV_PW"
check "$(imp "$R" alice)" 200 "rvadmin impersonates alice"
sleep 1
occ OC_PASS="$RV_PW-changed" user:resetpassword --password-from-env rvadmin >/dev/null
check "$(whoami_ "$R")" anonymous "impersonator password changed -> impersonation ends"
occ config:app:delete core last_check_timeout >/dev/null
setcfg impersonate_all_groupadmins false

echo "== D. invalid targets"
login "$A" admin "$ADMIN_PASSWORD"
check "$(imp "$A" admin)" 404 "self impersonation refused"
check "$(imp "$A" ADMIN)" 404 "self impersonation (other case) refused"
occ user:disable bob >/dev/null
check "$(imp "$A" bob)" 404 "disabled user refused"; command grep -q userDisabled "$W/body" && ok "error userDisabled" || bad "body $(cat "$W/body")"
occ user:enable bob >/dev/null
check "$(whoami_ "$A")" admin "admin unaffected"

echo "== E. removed routes"
for r in logout settings/impersonatetemplate; do
	check "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/index.php/apps/impersonate/$r")" 302 "anonymous POST /apps/impersonate/$r -> login redirect (no 500)"
	code=$(curl -s -o /dev/null -w '%{http_code}' -b "$A" -H "requesttoken: $(token "$A")" -X POST "$BASE/index.php/apps/impersonate/$r")
	case "$code" in 404|302|303) ok "admin POST /apps/impersonate/$r -> $code (route gone, no 500)" ;; *) bad "admin POST /apps/impersonate/$r -> $code" ;; esac
done

echo "== F. delegation policy only revealed to users who can impersonate"
login "$Bj" bob "$USER_PASSWORD"
check "$(curl -s -b "$Bj" -H "requesttoken: $(token "$Bj")" "$BASE/index.php/apps/impersonate/getimpersonatedata")" '["[]","false","false",false,false,"[]"]' "normal user gets no policy"
setcfg impersonate_include_groups true; setcfg impersonate_include_groups_list '["g1","g2"]'
occ group:add-member g1 -m dave >/dev/null
login "$C" carol "$USER_PASSWORD"
check "$(curl -s -b "$C" -H "requesttoken: $(token "$C")" "$BASE/index.php/apps/impersonate/getimpersonatedata")" '["[\"g1\"]","true","false",false,true,"[\"dave\"]"]' "group admin sees own groups and the admins in them"
check "$(imp "$C" dave)" 404 "group admin can not impersonate an admin of their group"
occ group:remove-member g1 -m dave >/dev/null

echo "== G. leftover group list while 'only admins' is selected"
setcfg impersonate_include_groups false
check "$(imp "$C" alice)" 404 "carol refused although the list contains g1"

echo "== H. malformed configuration does not break the admin page"
for value in '' 'null' '"g1"' '[["g1"]]' '{"a":1}' 'garbage'; do
	setcfg impersonate_include_groups_list "$value"
	login "$A" admin "$ADMIN_PASSWORD"
	code=$(curl -s -o "$W/p" -w '%{http_code}' -b "$A" "$BASE/index.php/settings/admin?sectionid=authentication")
	if [ "$code" = 200 ] && command grep -q impersonateTemplateSettings "$W/p"; then ok "admin page renders with list=$value"; else bad "admin page $code with list=$value"; fi
done
setcfg impersonate_include_groups_list '[]'

echo "== I. group admin feature hint"
occ config:system:set allow_subadmins --value=false --type=boolean >/dev/null
login "$A" admin "$ADMIN_PASSWORD"
curl -s -b "$A" "$BASE/index.php/settings/admin?sectionid=authentication" | command grep -q impersonateGroupAdminsDisabledHint && ok "hint shown when allow_subadmins=false" || bad "hint missing"
occ config:system:set allow_subadmins --value=true --type=boolean >/dev/null
curl -s -b "$A" "$BASE/index.php/settings/admin?sectionid=authentication" | command grep -q impersonateGroupAdminsDisabledHint && bad "hint shown although allow_subadmins=true" || ok "no hint when allow_subadmins=true"

echo "== J. basic auth request (as used by the API acceptance tests)"
J=$W/basic
code=$(curl -s -o "$W/j" -w '%{http_code}' -c "$J" -u "admin:$ADMIN_PASSWORD" -X POST "$BASE/index.php/apps/impersonate/user" --data-urlencode target=alice)
check "$code" 200 "basic auth impersonate"
check "$(whoami_ "$J")" alice "basic auth session cookie is now alice"
logout "$J" >/dev/null
check "$(whoami_ "$J")" admin "basic auth session returns to admin on logout"

echo "== K. requests that run concurrently with the switch"
login "$A" admin "$ADMIN_PASSWORD"
T=$(token "$A"); cp "$A" "$W/admin-stale"
curl -s -o /dev/null -c "$A" -b "$A" -H "requesttoken: $T" -X POST "$BASE/index.php/apps/impersonate/user" --data-urlencode target=alice &
sleep 0.05
curl -s -D "$W/stale-headers" -o /dev/null -b "$W/admin-stale" -H 'OCS-APIREQUEST: true' "$BASE/ocs/v1.php/cloud/user?format=json"
wait
command grep -qi 'oc_sessionPassphrase=deleted' "$W/stale-headers" && bad "a stale concurrent request logged the browser out" || ok "a stale concurrent request does not log the browser out"
check "$(whoami_ "$A")" alice "the switched session is intact"
logout "$A" >/dev/null
check "$(whoami_ "$A")" admin "switched back"
check "$(sql "select count(*) from oc_authtoken where id>$MARK and name like 'Impersonated by %'")" 0 "no orphaned impersonation tokens"

finish
