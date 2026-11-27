#!/bin/bash
# Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
# Original author: Marek Królikowski (TaKeN)
# Original project: https://github.com/takenek/impersonate
# SPDX-License-Identifier: AGPL-3.0-or-later
# See LICENSE and COPYRIGHT for the license and the AGPL section 7 attribution terms.
#
# Impersonation with server side encryption (the encryption app of ownCloud with a master key, which
# is what "occ encryption:enable" sets up on ownCloud 11.1): the impersonated session reads the
# encrypted files of the impersonated user, and returning restores exactly the encryption state the
# impersonator's session had before (SECURITY.md, "Session values of other apps").
#
# Enables encryption on the instance and leaves it enabled: run it after the other tests.
# Expects the users of setup-users.sh. Environment: see lib.sh.
. "$(dirname "$0")/lib.sh"
trap 'rm -rf "$W"; reset_policy; occ impersonate:active --end >/dev/null 2>&1' EXIT
reset_policy
A=$W/admin; U=$W/alice

occ app:enable encryption >/dev/null 2>&1
occ encryption:enable >/dev/null 2>&1
occ encryption:status | command grep -q 'enabled: true' && ok "server side encryption is enabled" || bad "encryption could not be enabled"
check "$(occ config:app:get encryption useMasterKey)" 1 "... with a master key"

# the encryption state of a session as the test helper shows it: flags, and which keys there are
state() { sess "$1" | command grep -E '^  (encryptionInitialized|privateKey|impersonatorEncryptionInitialized|impersonatorPrivateKey) =>' | sort | tr -s ' \n' ' '; }
put() { curl -s -o /dev/null -w '%{http_code}' -b "$1" -c "$1" -H "requesttoken: $(token "$1")" -X PUT --data-binary "$3" "$BASE/remote.php/webdav/$2"; }
get() { curl -s -b "$1" -c "$1" -H "requesttoken: $(token "$1")" "$BASE/remote.php/webdav/$2"; }
stored() { case "$1" in 201|204) return 0 ;; esac; return 1; }

# the keys of a session are set up by a login
login "$U" alice "$USER_PASSWORD"; check "$(whoami_ "$U")" alice "alice logged in"
login "$A" admin "$ADMIN_PASSWORD"; check "$(whoami_ "$A")" admin "admin logged in"
stored "$(put "$U" e2e-encrypted-alice.txt 'the file of alice')" && ok "alice stores a file" || bad "alice could not store a file"
stored "$(put "$A" e2e-encrypted-admin.txt 'the file of admin')" && ok "admin stores a file" || bad "admin could not store a file"
check "$(sql "select count(*) from oc_filecache where name in ('e2e-encrypted-alice.txt', 'e2e-encrypted-admin.txt') and encrypted > 0")" 2 "both files are encrypted on the server"

BEFORE=$(state "$A")
[ -n "$BEFORE" ] && ok "the session of admin has an encryption state ($BEFORE)" || bad "no encryption state in the session of admin (cannot test its restoration)"
check "$(imp "$A" alice)" 200 "admin impersonates alice"
state "$A" | command grep -q 'impersonatorEncryptionInitialized' && ok "the encryption state of the impersonator is kept aside" || bad "no copy of the impersonator's encryption state: $(state "$A")"
check "$(get "$A" e2e-encrypted-alice.txt)" 'the file of alice' "the impersonated session reads the encrypted file of alice"
logout "$A" >/dev/null; check "$(whoami_ "$A")" admin "admin returned"
check "$(state "$A")" "$BEFORE" "the encryption state of the session is exactly what it was before"
check "$(get "$A" e2e-encrypted-admin.txt)" 'the file of admin' "admin reads the own encrypted file after returning"
check "$(get "$U" e2e-encrypted-alice.txt)" 'the file of alice' "alice reads the own encrypted file"
check "$(active_records)" 0 "no impersonation is left"

for f in "$U:e2e-encrypted-alice.txt" "$A:e2e-encrypted-admin.txt"; do
	curl -s -o /dev/null -b "${f%%:*}" -c "${f%%:*}" -H "requesttoken: $(token "${f%%:*}")" -X DELETE "$BASE/remote.php/webdav/${f##*:}"
done
finish
