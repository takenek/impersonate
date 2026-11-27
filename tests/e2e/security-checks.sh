#!/bin/bash
# Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
# Original author: Marek Królikowski (TaKeN)
# Original project: https://github.com/takenek/impersonate
# SPDX-License-Identifier: AGPL-3.0-or-later
# See LICENSE and COPYRIGHT for the license and the AGPL section 7 attribution terms.
#
# Live checks of the security properties of the impersonate app (see SECURITY.md):
# session isolation, session id / CSRF rotation, password-bound token after switching back, refused
# credential minting (all path forms), per-request re-validation (web, OCS, WebDAV), maximum
# duration, invalid targets, removed routes, policy disclosure and storage, malformed configuration,
# starts without an interactive session, concurrent requests during the switch, the credential
# cleanup and its notification, impersonations that end without a logout (reconcile job, occ),
# the session token of an impersonation used outside its session.
# Expects the users of setup-users.sh. Environment: see lib.sh. Uses only throw-away rv* accounts
# and e2e-* fixtures.
. "$(dirname "$0")/lib.sh"
restore() {
	reset_policy
	for u in alice bob carol dave; do occ user:enable "$u" >/dev/null 2>&1; done
	occ group:remove-member g1 -m dave >/dev/null 2>&1
	occ user:delete rvadmin >/dev/null 2>&1
	occ group:delete e2e-group >/dev/null 2>&1
	occ config:app:delete core last_check_timeout >/dev/null 2>&1
	occ config:app:delete impersonate max_duration_minutes >/dev/null 2>&1
	occ config:app:delete impersonate forbidden_prefixes >/dev/null 2>&1
	occ config:app:delete impersonate allow_start_with_credentials >/dev/null 2>&1
	occ config:system:set allow_subadmins --value=true --type=boolean >/dev/null
	ocs_admin -X DELETE "$BASE/ocs/v1.php/cloud/users/alice/subadmins" -d groupid=g2 >/dev/null 2>&1
	occ impersonate:active --end >/dev/null 2>&1
	sqlx "delete from oc_authtoken where name like 'e2e-%'" 2>/dev/null
	sqlx "delete from oc_notifications where app='impersonate'" 2>/dev/null
	sqlx "delete from oc_preferences where configkey='signing-key' and userid in ('alice','bob')" 2>/dev/null
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
check "$(active_records)" 1 "the server has a record of the active impersonation"
check "$(sql "select count(*) from oc_jobs where class like '%Impersonate%Reconcile'")" 1 "the reconcile job is registered"

echo "== B. no lasting credentials can be obtained while impersonating"
BEFORE=$(sql "select count(*) from oc_authtoken where uid='alice' and type=1")
REFUSED=$(log_count 'Refused POST /settings/personal/authtokens for user "alice" while "admin" impersonates them')
# refused <code> <path>: 403 comes from the app. For the forms a web server may reject or tidy up
# itself (encoded slash, dot segments) its own 404 is as good: the request never arrives.
refused() {
	case "$2" in
		*%2F*|*/./*|*/../*) [ "$1" = 403 ] || [ "$1" = 404 ] ;;
		*) [ "$1" = 403 ] ;;
	esac
}
# every form of the path under which the platform could reach the operation (and forms it does not
# route at all): none may create a token. --path-as-is: curl must not tidy the path up.
for path in /index.php/settings/personal/authtokens /index.php//settings/personal/authtokens \
	/index.php/settings/personal/authtoken%73 /index.php/settings/personal%2Fauthtokens \
	/index.php/settings/personal/authtokens/ /index.php/settings//personal//authtokens \
	/index.php/Settings/Personal/AuthTokens /index.php/index.php/settings/personal/authtokens \
	/index.php/settings/personal/./authtokens /index.php/settings/personal/x/../authtokens; do
	code=$(curl -s --path-as-is -o /dev/null -w '%{http_code}' -b "$A" -c "$A" -H "requesttoken: $(token "$A")" -X POST "$BASE$path" -d name=e2e-evil)
	refused "$code" "$path" && ok "POST $path refused ($code)" || bad "POST $path -> $code"
done
check "$(sql "select count(*) from oc_authtoken where uid='alice' and type=1")" "$BEFORE" "no app password created for alice"
for path in /ocs/v1.php/cloud/user/signing-key /ocs/v2.php/cloud/user/signing-key /ocs/v1.php//cloud/user/signing-key \
	/ocs/v1.php/cloud/user%2Fsigning-key /ocs/v1.php/cloud/user/signing%2Dkey /ocs/v1.php/cloud/user/signing-key/ \
	/ocs/v1.php/Cloud/User/Signing-Key /index.php/ocs/cloud/user/signing-key /index.php/ocs/v1.php/cloud/user/signing-key; do
	for method in GET POST; do
		code=$(curl -s --path-as-is -o /dev/null -w '%{http_code}' -b "$A" -c "$A" -H 'OCS-APIREQUEST: true' -H "requesttoken: $(token "$A")" -X "$method" "$BASE$path?format=json")
		refused "$code" "$path" && ok "$method $path refused ($code)" || bad "$method $path -> $code"
	done
done
check "$(sql "select count(*) from oc_preferences where userid='alice' and configkey='signing-key'")" 0 "no URL signing key created for alice"
for path in /index.php/apps/oauth2/authorize /index.php/apps/OAuth2/authorize /index.php/apps/oauth2; do
	check "$(curl -s -o /dev/null -w '%{http_code}' -b "$A" -c "$A" "$BASE$path")" 403 "GET $path refused"
done
# what the operator added to the deny-list (app config "forbidden_prefixes")
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$A" -c "$A" "$BASE/index.php/apps/e2e-forbidden/x")
[ "$code" != 403 ] && ok "a path that is not on the deny-list is not refused by the guard ($code)" || bad "GET /apps/e2e-forbidden/x -> $code without a deny-list entry"
setcfg forbidden_prefixes '["/apps/e2e-forbidden/","/logout/","not-a-prefix"]'
check "$(curl -s -o /dev/null -w '%{http_code}' -b "$A" -c "$A" "$BASE/index.php/apps/e2e-forbidden/x")" 403 "a prefix added by the operator is refused"
check "$(curl -s -o /dev/null -w '%{http_code}' -b "$A" -c "$A" "$BASE/index.php/apps/E2E-Forbidden")" 403 "... in every letter case"
# the front page has no path info: it must keep working
for path in / /index.php /index.php/; do
	code=$(curl -s -o /dev/null -w '%{http_code}' -b "$A" -c "$A" "$BASE$path")
	case "$code" in 200|302|303) ok "GET $path is not refused ($code)" ;; *) bad "GET $path -> $code" ;; esac
done
check "$(curl -s -o /dev/null -w '%{http_code}' -b "$A" -c "$A" "$BASE/index.php/apps/files/")" 200 "the files app works while impersonating"
check "$(whoami_ "$A")" alice "still impersonating after the refused requests"
[ "$(log_count 'Refused POST /settings/personal/authtokens for user "alice" while "admin" impersonates them')" -gt "$REFUSED" ] && ok "the refusal is logged with the normalized path" || bad "refusal not logged"
# a prefix can not lock the impersonator in: "/logout/" is configured above
logout "$A" >/dev/null
occ config:app:delete impersonate forbidden_prefixes >/dev/null
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
check "$(active_records)" 0 "the record of the impersonation is closed"

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
check "$(active_records)" 0 "every forced end closed its record"
# the re-validation also runs for WebDAV requests that carry the session cookie
login "$C" carol "$USER_PASSWORD"; check "$(imp "$C" alice)" 200 "carol impersonates alice once more"
check "$(curl -s -o /dev/null -w '%{http_code}' -b "$C" -c "$C" -X PROPFIND -H 'Depth: 0' -H "requesttoken: $(token "$C")" "$BASE/remote.php/webdav/")" 207 "WebDAV works while impersonating"
occ user:disable carol >/dev/null
check "$(curl -s -o /dev/null -w '%{http_code}' -b "$C" -c "$C" -X PROPFIND -H 'Depth: 0' "$BASE/remote.php/webdav/")" 401 "impersonator disabled -> the WebDAV request is not served"
check "$(whoami_ "$C")" anonymous "... and the session has ended"
check "$(active_records)" 0 "... and its record is closed"
occ user:enable carol >/dev/null
setcfg impersonate_all_groupadmins false

echo "== C2. maximum duration"
setcfg max_duration_minutes 1
LOGGED=$(log_count 'the maximum duration of the impersonation was reached')
login "$A" admin "$ADMIN_PASSWORD"; check "$(imp "$A" alice)" 200 "admin impersonates alice (limit: 1 minute)"
check "$(whoami_ "$A")" alice "the impersonation is active"
sleep 62
check "$(whoami_ "$A")" anonymous "maximum duration reached -> impersonation ends with a logout"
check "$(active_records)" 0 "its record is closed"
check "$(( $(log_count 'the maximum duration of the impersonation was reached') - LOGGED ))" 1 "the reason is logged"
occ config:app:delete impersonate max_duration_minutes >/dev/null

echo "== C3. no login inside an impersonated session"
# The login form accepts the id of a session as the password of its user: from inside the
# impersonated session it would turn the session into a new one that nothing knows about (and a
# failed attempt would give the session a new id). The form is refused while impersonating.
login "$A" admin "$ADMIN_PASSWORD"; check "$(imp "$A" alice)" 200 "admin impersonates alice"
T=$(token "$A"); S1=$(sid "$A")
TOKENS=$(sql "select count(*) from oc_authtoken where uid='alice'")
check "$(curl -s -o /dev/null -w '%{http_code}' -c "$A" -b "$A" -X POST "$BASE/index.php/login" --data-urlencode "user=alice" --data-urlencode "password=$(rawsid "$A")" --data-urlencode "requesttoken=$T")" 403 "login with the own session id as the password: refused"
check "$(curl -s -o /dev/null -w '%{http_code}' -c "$A" -b "$A" -X POST "$BASE/index.php/login" --data-urlencode "user=alice" --data-urlencode "password=not-the-password" --data-urlencode "requesttoken=$T")" 403 "any other login attempt: refused"
[ "$(sid "$A")" = "$S1" ] && ok "the session kept its id" || bad "the session id changed"
check "$(sql "select count(*) from oc_authtoken where uid='alice'")" "$TOKENS" "no session token was created for alice"
check "$(whoami_ "$A")" alice "the impersonation goes on"
logout "$A" >/dev/null; check "$(whoami_ "$A")" admin "... and ends as usual"
check "$(sql "select count(*) from oc_authtoken where id>$MARK and name like 'Impersonated by %'")" 0 "the session token of the impersonation is revoked"
check "$(active_records)" 0 "the impersonation has ended"

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
# a member who administers another group is no target for a group admin unless that is allowed
ocs_admin -X POST "$BASE/ocs/v1.php/cloud/users/alice/subadmins" -d groupid=g2 >/dev/null
check "$(curl -s -b "$C" -H "requesttoken: $(token "$C")" "$BASE/index.php/apps/impersonate/getimpersonatedata")" '["[\"g1\"]","true","false",false,true,"[\"alice\"]"]' "group admin is told which members are group admins"
check "$(imp "$C" alice)" 404 "group admin can not impersonate a member who is a group admin"
check "$(whoami_ "$C")" carol "carol is still carol"
setcfg impersonate_allow_groupadmin_targets true
check "$(curl -s -b "$C" -H "requesttoken: $(token "$C")" "$BASE/index.php/apps/impersonate/getimpersonatedata")" '["[\"g1\"]","true","false",false,true,"[]"]' "... unless group admins are allowed as targets"
check "$(imp "$C" alice)" 200 "then carol impersonates alice"
logout "$C" >/dev/null; check "$(whoami_ "$C")" carol "carol returned"
setcfg impersonate_allow_groupadmin_targets false
ocs_admin -X DELETE "$BASE/ocs/v1.php/cloud/users/alice/subadmins" -d groupid=g2 >/dev/null

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

echo "== J. an impersonation can only be started from an interactive session"
J=$W/basic
REFUSALS=$(log_count 'refused: an impersonation must be started from an interactive session')
code=$(curl -s -o "$W/j" -w '%{http_code}' -c "$J" -u "admin:$ADMIN_PASSWORD" -X POST "$BASE/index.php/apps/impersonate/user" --data-urlencode target=alice)
check "$code" 404 "start with HTTP Basic credentials refused"
command grep -q cannotImpersonate "$W/j" && ok "... with the generic error" || bad "body: $(cat "$W/j")"
[ "$(whoami_ "$J")" != alice ] && ok "the session of the request is not alice" || bad "the HTTP Basic request got a session of alice"
check "$(curl -s -o /dev/null -w '%{http_code}' -c "$J" -u "admin:$ADMIN_PASSWORD" -H 'OCS-APIREQUEST: true' -X POST "$BASE/index.php/apps/impersonate/user" --data-urlencode target=alice)" 404 "... also as an API request"
# The platform gives a request with HTTP Basic credentials a session token of its own once it
# carries cookies, and does not ask it for the CSRF token: it is still not a browser session.
J2=$W/basic-cookies
check "$(curl -s -o /dev/null -w '%{http_code}' -c "$J2" -b 'cookie_test=test' -u "admin:$ADMIN_PASSWORD" -X POST "$BASE/index.php/apps/impersonate/user" --data-urlencode target=alice)" 404 "... also with a cookie"
check "$(curl -s -o /dev/null -w '%{http_code}' -c "$J2" -b "$J2" -u "admin:$ADMIN_PASSWORD" -X POST "$BASE/index.php/apps/impersonate/user" --data-urlencode target=alice)" 404 "... also with the session cookie of an earlier request"
TJ=$(curl -s -c "$J2" -b "$J2" -u "admin:$ADMIN_PASSWORD" "$BASE/index.php/apps/files/" | command grep -o 'data-requesttoken="[^"]*"' | head -1 | cut -d'"' -f2)
check "$(curl -s -o /dev/null -w '%{http_code}' -c "$J2" -b "$J2" -u "admin:$ADMIN_PASSWORD" -H "requesttoken: $TJ" -X POST "$BASE/index.php/apps/impersonate/user" --data-urlencode target=alice)" 404 "... also with that session's CSRF token"
[ "$(whoami_ "$J2")" != alice ] && ok "none of them got a session of alice" || bad "an HTTP Basic request got a session of alice"
# ... and neither is a later request of that session that brings no credentials anymore
check "$(whoami_ "$J2")" admin "the session the HTTP Basic request created is admin's"
check "$(curl -s -o /dev/null -w '%{http_code}' -c "$J2" -b "$J2" -H "requesttoken: $(token "$J2")" -X POST "$BASE/index.php/apps/impersonate/user" --data-urlencode target=alice)" 404 "start from a session that a request with credentials created: refused"
check "$(whoami_ "$J2")" admin "that session is still admin's"
# an app password of the administrator (a non-interactive credential, too)
login "$A" admin "$ADMIN_PASSWORD"
APP_PW=$(curl -s -b "$A" -c "$A" -H "requesttoken: $(token "$A")" -X POST "$BASE/index.php/settings/personal/authtokens" -d name=e2e-app-password \
	| php -r '$j = json_decode(stream_get_contents(STDIN), true); echo is_array($j) && is_string($j["token"] ?? null) ? $j["token"] : "";')
[ -n "$APP_PW" ] && ok "admin created an app password" || bad "no app password for the test"
code=$(curl -s -o /dev/null -w '%{http_code}' -c "$W/app-pw" -u "admin:$APP_PW" -X POST "$BASE/index.php/apps/impersonate/user" --data-urlencode target=alice)
check "$code" 404 "start with an app password refused"
[ "$(whoami_ "$W/app-pw")" != alice ] && ok "the session of the request is not alice" || bad "the app password request got a session of alice"
sqlx "delete from oc_authtoken where name='e2e-app-password'"
unset APP_PW
check "$(sql "select count(*) from oc_authtoken where id>$MARK and name like 'Impersonated by %'")" 0 "no impersonation token was created"
check "$(active_records)" 0 "no impersonation was recorded"
check "$(( $(log_count 'refused: an impersonation must be started from an interactive session') - REFUSALS ))" 7 "every refusal is logged"
check "$(whoami_ "$A")" admin "the interactive session of the administrator is unaffected"
# the operator can accept such starts (instances where every request of a browser carries credentials)
setcfg allow_start_with_credentials true
check "$(curl -s -o /dev/null -w '%{http_code}' -c "$J2" -b "$J2" -H "requesttoken: $(token "$J2")" -X POST "$BASE/index.php/apps/impersonate/user" --data-urlencode target=alice)" 200 "with allow_start_with_credentials the same request starts an impersonation"
check "$(whoami_ "$J2")" alice "the session is alice's"
logout "$J2" >/dev/null; check "$(whoami_ "$J2")" admin "... and returns to admin"
occ config:app:delete impersonate allow_start_with_credentials >/dev/null
check "$(active_records)" 0 "no impersonation is left"

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

echo "== L. the delegation policy is stored as a whole by administrators only"
put_policy() { # jar json -> HTTP status, body in $W/policy
	curl -s -o "$W/policy" -w '%{http_code}' -b "$1" -c "$1" -H "requesttoken: $(token "$1")" -H 'Content-Type: application/json' \
		-X PUT "$BASE/index.php/apps/impersonate/policy" --data "$2"
}
cfg() { occ config:app:get impersonate "$1"; }
occ group:add e2e-group >/dev/null
login "$A" admin "$ADMIN_PASSWORD"
check "$(put_policy "$A" '{"mode":"include_groups","groups":["g1","e2e-group","no-such-group",5],"allowGroupAdminTargets":true}')" 200 "admin stores a policy"
check "$(cat "$W/policy")" '{"policy":{"mode":"include_groups","groups":["g1","e2e-group"],"allowGroupAdminTargets":true}}' "the answer is the stored policy, without the group that does not exist"
check "$(cfg impersonate_include_groups_list)" '["g1","e2e-group"]' "the group list is stored"
check "$(cfg impersonate_include_groups)$(cfg impersonate_all_groupadmins)$(cfg impersonate_allow_groupadmin_targets)" truefalsetrue "the mode and the option are stored"
occ group:delete e2e-group >/dev/null
check "$(cfg impersonate_include_groups_list)" '["g1"]' "a deleted group leaves the list"
check "$(put_policy "$A" '{"mode":"everybody","groups":[]}')" 400 "an unknown mode is refused"
check "$(cfg impersonate_include_groups_list)$(cfg impersonate_include_groups)" '["g1"]true' "... and changes nothing"
check "$(curl -s -o /dev/null -w '%{http_code}' -b "$A" -c "$A" -H 'Content-Type: application/json' -X PUT "$BASE/index.php/apps/impersonate/policy" --data '{"mode":"all_groupadmins"}')" 412 "without the CSRF token: refused"
login "$C" carol "$USER_PASSWORD"
check "$(put_policy "$C" '{"mode":"all_groupadmins","groups":[],"allowGroupAdminTargets":true}')" 403 "a group admin can not store a policy"
login "$Bj" bob "$USER_PASSWORD"
check "$(put_policy "$Bj" '{"mode":"all_groupadmins","groups":[],"allowGroupAdminTargets":true}')" 403 "a normal user can not store a policy"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -X PUT "$BASE/index.php/apps/impersonate/policy" --data '{"mode":"all_groupadmins"}')
case "$code" in 302|303|401) ok "anonymous: sent to the login ($code)" ;; *) bad "anonymous PUT policy -> $code" ;; esac
check "$(cfg impersonate_all_groupadmins)$(cfg impersonate_include_groups)" falsetrue "the refused requests changed nothing"
# an administrator as the target, so that only the impersonation stands in the way
check "$(imp "$A" dave)" 200 "admin impersonates the administrator dave"
check "$(whoami_ "$A")" dave "the session is dave's"
check "$(put_policy "$A" '{"mode":"all_groupadmins","groups":[]}')" 403 "the policy can not be changed from an impersonated session"
logout "$A" >/dev/null
check "$(whoami_ "$A")" admin "admin returned"
check "$(put_policy "$A" '{"mode":"admins","groups":["g1"],"allowGroupAdminTargets":false}')" 200 "admin stores 'only administrators'"
check "$(cat "$W/policy")" '{"policy":{"mode":"admins","groups":[],"allowGroupAdminTargets":false}}' "... which has no group list"
check "$(cfg impersonate_include_groups_list)$(cfg impersonate_include_groups)$(cfg impersonate_all_groupadmins)$(cfg impersonate_allow_groupadmin_targets)" '[]falsefalsefalse' "all four values are stored"
page=$(curl -s -b "$A" "$BASE/index.php/settings/admin?sectionid=authentication")
echo "$page" | command grep -q 'id="impersonateGroupAdminTargets"' && ok "the admin page has the group admin target option" || bad "option missing on the admin page"
echo "$page" | command grep -q 'data-groups="\[\]"' && ok "the admin page carries the group list as JSON" || bad "no JSON group list on the admin page"
echo "$page" | command grep -q 'id="impersonateMaxDurationHint"' && ok "the admin page shows the maximum duration" || bad "no maximum duration hint"
echo "$page" | command grep -q 'id="impersonate.*ForbiddenPrefixes"' && bad "the admin page shows deny-list entries although none is set" || ok "no deny-list additions shown when none is set"
setcfg forbidden_prefixes '["/apps/e2e-forbidden","no-prefix"]'
page=$(curl -s -b "$A" "$BASE/index.php/settings/admin?sectionid=authentication")
echo "$page" | command grep -A2 'id="impersonateForbiddenPrefixes"' | command grep -q '/apps/e2e-forbidden/' && ok "the admin page shows the additions to the deny-list" || bad "deny-list additions not shown"
echo "$page" | command grep -A2 'id="impersonateIgnoredForbiddenPrefixes"' | command grep -q 'no-prefix' && ok "... and names an entry that is ignored" || bad "ignored deny-list entry not named"
occ config:app:delete impersonate forbidden_prefixes >/dev/null

echo "== M. credentials that appear during an impersonation do not outlive it; the owner is told"
occ app:enable notifications >/dev/null 2>&1
NOTES=$(sql "select count(*) from oc_notifications where app='impersonate' and user='alice'")
mint() { # a passwordless app password, as one created from an impersonated session would be
	sqlx "insert into oc_authtoken (uid, login_name, password, name, token, type, last_activity, last_check) values ('$1', '$1', NULL, '$2', '$(php -r 'echo hash("sha512", random_bytes(32));')', 1, strftime('%s','now'), strftime('%s','now'))"
}
mint alice e2e-before
login "$A" admin "$ADMIN_PASSWORD"; check "$(imp "$A" alice)" 200 "admin impersonates alice"
mint alice e2e-during
# a session without a stored password, as one that was logged in with the session id of the impersonation
sqlx "insert into oc_authtoken (uid, login_name, password, name, token, type, last_activity, last_check) values ('alice', 'alice', NULL, 'e2e-derived-session', '$(php -r 'echo hash("sha512", random_bytes(32));')', 0, strftime('%s','now'), strftime('%s','now'))"
occ user:setting alice core signing-key --value=e2e-signing-key >/dev/null
logout "$A" >/dev/null; check "$(whoami_ "$A")" admin "admin returned"
check "$(sql "select count(*) from oc_authtoken where name='e2e-during'")" 0 "the app password that appeared during the impersonation is revoked"
check "$(sql "select count(*) from oc_authtoken where name='e2e-derived-session'")" 0 "a passwordless session that appeared during the impersonation is revoked"
check "$(sql "select count(*) from oc_authtoken where name='e2e-before'")" 1 "an older one is kept"
check "$(sql "select count(*) from oc_preferences where userid='alice' and configkey='signing-key'")" 0 "the URL signing key that appeared is removed"
check "$(( $(sql "select count(*) from oc_notifications where app='impersonate' and user='alice'") - NOTES ))" 3 "alice got a notification for each"
check "$(sql "select count(*) from oc_notifications where app='impersonate' and user<>'alice'")" 0 "nobody else got one"
login "$Bj" alice "$USER_PASSWORD"
curl -s -b "$Bj" -H 'OCS-APIREQUEST: true' "$BASE/ocs/v2.php/apps/notifications/api/v1/notifications?format=json" > "$W/notifications"
command grep -q 'e2e-during.* was revoked for security reasons' "$W/notifications" && ok "the notification names the revoked app password" || bad "notification text not found"
sqlx "delete from oc_notifications where app='impersonate'"
sqlx "delete from oc_authtoken where name like 'e2e-%'"

echo "== N. an impersonation whose session is lost is ended and cleaned up by the reconcile job"
run_job() { occ background:queue:execute --force --accept-warning "$JOB" >/dev/null 2>&1; }
login "$A" admin "$ADMIN_PASSWORD"; check "$(imp "$A" bob)" 200 "admin impersonates bob"
JOB=$(sql "select id from oc_jobs where class like '%Impersonate%Reconcile'")
[ -n "$JOB" ] && ok "the reconcile job is on the job list" || bad "no reconcile job"
run_job
check "$(active_records)" 1 "the job leaves an impersonation that is in use alone"
check "$(whoami_ "$A")" bob "... its session goes on"
mint bob e2e-during
# the session expires: what is left of it is cleaned up by core, no logout ever runs
sqlx "delete from oc_authtoken where uid='bob' and name='Impersonated by admin'"
ENDED=$(log_count 'ended without a logout: the impersonated session expired or was revoked')
run_job
check "$(active_records)" 0 "the job closes the record"
check "$(sql "select count(*) from oc_authtoken where name='e2e-during'")" 0 "... and runs the credential cleanup"
check "$(( $(log_count 'ended without a logout: the impersonated session expired or was revoked') - ENDED ))" 1 "... and reports the end"
check "$(whoami_ "$A")" anonymous "the lost session can not be used anymore"
# the same user is impersonated again before the job has dealt with the first impersonation: the
# cleanup of the first one must not touch the session of the second
login "$A" admin "$ADMIN_PASSWORD"; check "$(imp "$A" bob)" 200 "admin impersonates bob"
sqlx "delete from oc_authtoken where uid='bob' and name='Impersonated by admin'"
A2=$W/admin-again; login "$A2" admin "$ADMIN_PASSWORD"; check "$(imp "$A2" bob)" 200 "admin impersonates bob again in another browser"
check "$(active_records)" 2 "two impersonations are recorded"
run_job
check "$(active_records)" 1 "the job closes the record of the lost one"
check "$(whoami_ "$A2")" bob "... and leaves the session of the other one alone"
logout "$A2" >/dev/null; check "$(whoami_ "$A2")" admin "which ends as usual"
check "$(active_records)" 0 "no record is left"
sqlx "delete from oc_notifications where app='impersonate'"

echo "== O. an administrator ends active impersonations (occ impersonate:active)"
check "$(occ impersonate:active)" "No active impersonations." "nothing is active"
BY_ADMIN=$(log_count 'ended by an administrator')
login "$A" admin "$ADMIN_PASSWORD"; check "$(imp "$A" alice)" 200 "admin impersonates alice"
occ impersonate:active | command grep -q '^admin impersonates alice since ' && ok "the impersonation is listed" || bad "impersonation not listed"
check "$(whoami_ "$A")" alice "listing does not end it"
occ impersonate:active --end | command grep -q '^Ended 1 impersonation(s).$' && ok "occ impersonate:active --end ends it" || bad "not ended"
check "$(active_records)" 0 "its record is closed"
check "$(whoami_ "$A")" anonymous "its session is logged out"
check "$(sql "select count(*) from oc_authtoken where id>$MARK and name like 'Impersonated by %'")" 0 "no impersonation tokens are left"
check "$(( $(log_count 'ended by an administrator') - BY_ADMIN ))" 1 "the reason is logged"
check "$(sql "select count(*) from oc_jobs where class like '%Impersonate%Reconcile'")" 0 "with nothing left to do the background job is off the job list (the app can be disabled)"
login "$A" admin "$ADMIN_PASSWORD"; check "$(imp "$A" alice)" 200 "admin impersonates alice"
check "$(sql "select count(*) from oc_jobs where class like '%Impersonate%Reconcile'")" 1 "the next impersonation registers the job again"
logout "$A" >/dev/null

echo "== P. the session token of an impersonation is no credential outside its session"
# The platform accepts the id of a session as the password of HTTP Basic authentication and as a
# token of its user. For an impersonated session that would be a way around every check of the
# app: such a request is refused and ends the impersonation.
own=$W/alice-own; login "$own" alice "$USER_PASSWORD"
# decoys <n>: n query parameters whose values have the shape of a session id of this server
decoys() {
	php -r '
		$length = (int)ini_get("session.sid_length");
		$length = $length >= 22 && $length <= 256 ? $length : 32;
		for ($i = 0; $i < (int)$argv[1]; $i++) { echo "d$i=", substr(str_repeat(md5("decoy $i"), 8), 0, $length), "&"; }
		echo "x=1";
	' "$1"
}
misuse() { # <how the session id is presented> <description>
	local how=$1 what=$2 code SI before
	login "$A" admin "$ADMIN_PASSWORD"
	[ "$(imp "$A" bob)" = 200 ] || bad "admin could not impersonate bob"
	SI=$(rawsid "$A")
	before=$(log_count 'that is not part of the impersonated session (from')
	case "$how" in
		basic) code=$(curl -s -o /dev/null -w '%{http_code}' -u "bob:$SI" -H 'OCS-APIREQUEST: true' "$BASE/ocs/v1.php/cloud/user/signing-key?format=json") ;;
		token) code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: token $SI" -H 'OCS-APIREQUEST: true' "$BASE/ocs/v1.php/cloud/user/signing-key?format=json") ;;
		webdav) code=$(curl -s -o /dev/null -w '%{http_code}' -u "bob:$SI" -X PROPFIND -H 'Depth: 0' "$BASE/remote.php/webdav/") ;;
		authtokens) code=$(curl -s -o /dev/null -w '%{http_code}' -u "bob:$SI" -X POST "$BASE/index.php/settings/personal/authtokens" -d name=e2e-evil) ;;
		loginform|loginform-json|loginform-decoys)
			rm -f "$W/fresh"
			code=$(curl -s -c "$W/fresh" -b "$W/fresh" "$BASE/index.php/login" | command grep -o 'data-requesttoken="[^"]*"' | head -1 | cut -d'"' -f2)
			case "$how" in
				loginform) code=$(curl -s -o /dev/null -w '%{http_code}' -c "$W/fresh" -b "$W/fresh" -X POST "$BASE/index.php/login" --data-urlencode "user=bob" --data-urlencode "password=$SI" --data-urlencode "requesttoken=$code" -d timezone=UTC -d timezone-offset=0) ;;
				loginform-json) code=$(curl -s -o /dev/null -w '%{http_code}' -c "$W/fresh" -b "$W/fresh" -X POST "$BASE/index.php/login" -H 'Content-Type: application/json' -H "requesttoken: $code" --data "$(php -r 'echo json_encode(["user" => "bob", "password" => $argv[1]]);' "$SI")") ;;
				# other values in the shape of a session id in front of the password
				loginform-decoys) code=$(curl -s -o /dev/null -w '%{http_code}' -c "$W/fresh" -b "$W/fresh" -X POST "$BASE/index.php/login?$(decoys 12)" --data "$(decoys 200)" --data-urlencode "user=bob" --data-urlencode "password=$SI" --data-urlencode "requesttoken=$code") ;;
			esac ;;
	esac
	check "$code" 401 "$what: refused"
	check "$(( $(log_count 'that is not part of the impersonated session (from') - before ))" 1 "$what: logged"
	check "$(active_records)" 0 "$what: the impersonation is ended"
	check "$(sql "select count(*) from oc_authtoken where id>$MARK and name like 'Impersonated by %'")" 0 "$what: its session token is revoked"
	check "$(whoami_ "$A")" anonymous "$what: the impersonated session is over"
}
misuse basic "session id as the password of HTTP Basic authentication"
misuse token "session id as a token"
misuse webdav "session id as the password of a WebDAV request"
misuse authtokens "session id as the password of a request for an app password"
BOBS=$(sql "select count(*) from oc_authtoken where uid='bob'")
misuse loginform "session id as the password of the login form"
[ "$(whoami_ "$W/fresh")" != bob ] && ok "the login form did not log anybody in as bob" || bad "the login form created a session of bob"
misuse loginform-json "session id as the password of the login form (JSON body)"
[ "$(whoami_ "$W/fresh")" != bob ] && ok "the login form did not log anybody in as bob" || bad "the login form created a session of bob"
misuse loginform-decoys "session id as the password behind other values of the same shape"
[ "$(whoami_ "$W/fresh")" != bob ] && ok "the login form did not log anybody in as bob" || bad "the login form created a session of bob"
check "$(sql "select count(*) from oc_authtoken where uid='bob'")" "$BOBS" "no session token was created for bob"
# a request with more such values than any request needs is not looked at any further: it is refused
login "$A" admin "$ADMIN_PASSWORD"; check "$(imp "$A" bob)" 200 "admin impersonates bob"
rm -f "$W/fresh"; tok=$(curl -s -c "$W/fresh" -b "$W/fresh" "$BASE/index.php/login" | command grep -o 'data-requesttoken="[^"]*"' | head -1 | cut -d'"' -f2)
check "$(curl -s -o /dev/null -w '%{http_code}' -c "$W/fresh" -b "$W/fresh" -X POST "$BASE/index.php/login" --data "$(decoys 300)" --data-urlencode "user=bob" --data-urlencode "password=$(rawsid "$A")" --data-urlencode "requesttoken=$tok")" 503 "a request with hundreds of values in the shape of a session id: refused"
[ "$(whoami_ "$W/fresh")" != bob ] && ok "... and nobody is logged in as bob" || bad "the login form created a session of bob"
check "$(sql "select count(*) from oc_authtoken where uid='bob'")" "$((BOBS + 1))" "only the session token of the impersonation exists for bob"
check "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/index.php/apps/impersonate/nothing" --data "$(decoys 300)")" 503 "(while an impersonation is active this holds for every such request)"
[ "$(log_count 'too many request values')" = 0 ] && ok "... and nothing an anonymous client can fill the log with (default log level)" || bad "the refusal was written to the log"
logout "$A" >/dev/null; check "$(whoami_ "$A")" admin "admin returned"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/index.php/apps/impersonate/nothing" --data "$(decoys 300)")
[ "$code" != 503 ] && ok "without an active impersonation requests are not looked at ($code)" || bad "a request was refused without an active impersonation"
check "$(sql "select count(*) from oc_preferences where userid='bob' and configkey='signing-key'")" 0 "no URL signing key was obtained for bob"
check "$(sql "select count(*) from oc_authtoken where name='e2e-evil'")" 0 "no app password was created for bob"
# what is none of the app's business stays as it is: the session of another user, presented the same
# way while an impersonation is active
login "$A" admin "$ADMIN_PASSWORD"; check "$(imp "$A" bob)" 200 "admin impersonates bob"
check "$(curl -s -u "alice:$(rawsid "$own")" -H 'OCS-APIREQUEST: true' "$BASE/ocs/v1.php/cloud/user?format=json" | php -r '$j = json_decode(stream_get_contents(STDIN), true); echo $j["ocs"]["data"]["id"] ?? "anonymous";')" alice "requests with other credentials are not affected"
check "$(whoami_ "$own")" alice "other sessions are not affected"
check "$(whoami_ "$A")" bob "... and neither is the impersonation"
logout "$A" >/dev/null; check "$(whoami_ "$A")" admin "admin returned"

finish
