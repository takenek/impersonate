# Security policy – Impersonate for ownCloud 11

## Reporting a vulnerability

Please report vulnerabilities **privately** through GitHub's private vulnerability reporting:
<https://github.com/takenek/impersonate/security/advisories/new>. Do not open public issues for
security problems. Include the version, the ownCloud version, steps to reproduce and the impact.
You will get an answer within a few working days; fixes are released as a new patch version with a
GitHub security advisory.

## Supported versions

| Version | ownCloud | PHP | Supported |
|---|---|---|---|
| 1.0.x | 11.x (tested 11.1.0) | 8.3 | yes |
| 0.x (owncloud/impersonate) | 10.x / 11.x | 7.4 – 8.3 | no (upstream archived) |

## Release signing key

Release tags (`vX.Y.Z`) are annotated tags signed with the maintainer's SSH key. CI accepts a release
only if its tag verifies against [.github/release-signers](.github/release-signers) as it is on
`main`, and only then builds and attaches the release archive.

```
principal:   impersonate-release
key:         RSA 8192
fingerprint: SHA256:Dh488r7YcvACwpsZov0/TASb3v3FRjz4//bwoQCyPwU
```

Compare the fingerprint with the maintainer's GitHub signing keys
(<https://api.github.com/users/takenek/ssh_signing_keys>); the file alone, taken from the same clone
as the tag, proves nothing.

### Verifying a release

```bash
# the archive matches the checksum published with the release
sha256sum -c impersonate-1.0.3.tar.gz.sha256

# the tag is signed by the release key
git clone https://github.com/takenek/impersonate.git && cd impersonate
git -c gpg.ssh.allowedSignersFile=.github/release-signers verify-tag v1.0.3

# the archive can be rebuilt from the tag (reproducible: same content, same checksum)
git checkout v1.0.3 && make dist && cat build/impersonate-1.0.3.tar.gz.sha256
```

CI builds the archive from the commit the verified tag names and never replaces an archive that is
published: a second run of the release job compares the published files with the ones it built and
fails if they differ. The verification is a step of the workflow of the tagged commit, so it guards against
mistakes; against somebody who can write to the repository, the tag rules of the repository
(creation by the maintainer only, no moving or deleting) and the three checks above are what counts.

The app is not signed with an ownCloud code signing certificate (only ownCloud can issue those), see
README section 2 for `integrity.ignore.missing.app.signature`. ownCloud's integrity check therefore
does not notice a change of the installed files: install them read-only for the web server (README
section 2) and compare an installation with the verified archive when in doubt. This document is
part of the release archive (`impersonate/SECURITY.md`).

## Security model

Impersonation gives the impersonator the complete identity of the impersonated user for the duration
of the session. The app is designed so that

1. **only authorized users can start it, from an interactive session** – administrators (any enabled
   user except themselves) and, if configured and `allow_subadmins` is enabled, group admins (enabled
   members of the groups they may impersonate in who are neither administrators nor – unless that is
   allowed explicitly – group admins); the decision is made in one place (`lib/Policy.php`) and
   users who may not impersonate learn nothing about other accounts. The request that starts an
   impersonation must be authenticated by the session cookie of a login in the web interface and by
   nothing else: a request that carries credentials (HTTP Basic, an app password, a token) is
   refused before anything is changed, and so is a session that such a request created (ownCloud
   gives it one once it carries a cookie, without asking for the CSRF token; the session then holds
   the marker of HTTP Basic authentication or the token it was logged in with). The session must
   have a session token that belongs to the user. Instances where every request of a browser
   carries credentials (authentication by a proxy or by the web server) can turn these two checks
   off with the app config `allow_start_with_credentials`, and accept what they guard against. The
   user interface asks for confirmation and names the account; the account is the one the icon was
   created for, never the text shown in the row;
2. **nothing of the impersonator leaks into the impersonated session** – the impersonator's login
   name, the login password that core keeps for "Log-in credentials, save in session" external
   storages, app password and DAV markers are moved out of the session and restored afterwards; the
   session id and the CSRF token are rotated on every switch;
3. **credentials that would outlive the impersonation cannot be obtained through the operations on
   the deny-list** – creating an app password (`POST /settings/personal/authtokens`), reading or
   creating the URL signing key for pre-signed WebDAV URLs (`/cloud/user/signing-key`, any method),
   everything of the OAuth2 app (`/apps/oauth2/`), a login through the login form (`POST /login`,
   which accepts the id of a session as a password and would turn the impersonated session into a
   new one) and everything below the prefixes the operator adds (app config `forbidden_prefixes`). The request path is normalized (repeated slashes, URL encoding,
   trailing slash) and compared without regard to letter case and to the entry point
   (`index.php`, `ocs/v1.php`, `ocs/v2.php`); a request whose path cannot be determined is refused.
   This is a list, not a default-deny rule: an operation of ownCloud or of another installed app
   that issues a credential or changes how an account is recovered and is not on the list is not
   blocked – add its prefix. As a backstop, tokens of the user without a stored password that
   appeared during the impersonation are revoked – app passwords created from the impersonated
   session have none, nor has a session that was logged in with the session id of the impersonation
   – and a URL signing key that appeared is removed when the impersonation ends, whichever way it
   ends (point 6). The session of another impersonation of the same user is left alone. A signing
   key the user already had is protected by the deny-list only;
4. **it ends when the authorization ends** – it is re-checked on every request (after all
   authentication apps are loaded; verified for the web interface, the OCS API and WebDAV of
   ownCloud 11.1.0): it ends with a full logout when the impersonator is deleted or disabled, loses
   the permission, the maximum duration is reached (app config `max_duration_minutes`, 60 by
   default), the impersonator's parked session is revoked, or the impersonator changes the password.
   The password is checked like core does, every `last_check_timeout` minutes, and only for
   impersonations that were started from a session with a stored login password; a session without
   one (e.g. single sign-on) has nothing to re-check and is bounded by the maximum duration. If the
   check itself fails (e.g. a user or group backend is down), the request is refused with HTTP 503
   instead of being served without the check;
5. **only the user's own logout switches back** – a logout that core triggers for security reasons
   (revoked or invalid session, auth header mismatch, password reset) ends the session instead; the
   switch back requires the CSRF token of the logout link. A switch – in either direction – that
   fails half-way ends in a logged-out session whose token is revoked;
6. **it is visible and audited** – the impersonated user sees the session as
   "Impersonated by &lt;uid&gt;" and can revoke it; the impersonator's own session stays listed (and
   revocable) in their session list; every start, every end and every refusal is logged at warning
   level with the canonical uids (and the remote address where a request causes it), and the events
   `user.afterimpersonate` and `user.afterimpersonatelogout` (with the arguments `impersonator`,
   `targetUser` and, for the end, `reason`) are dispatched (consumed e.g. by audit apps). Every
   impersonation has a server-side record: one whose session just expires or is lost is ended,
   cleaned up (point 3) and reported by a background job. That happens when the job runs more than
   two minutes after the maximum duration has passed, or after the session token is gone – not at
   the moment the session expires, and not at all if the background jobs of the instance do not run;
7. **the owner learns about revoked credentials** – the cleanup of point 3 cannot tell who created a
   credential, so it also removes one the account owner created during the impersonation: an app
   password created from a session without a login password, or such a session itself (e.g. after
   single sign-on; a session or app password with a stored password is never touched). For each
   removed credential the owner gets a notification (notifications app), a warning is logged and the
   event `user.impersonate.credentialrevoked` is dispatched;
8. **the session of an impersonation is no credential** – ownCloud accepts the id of a session as a
   token of its user: as the password of HTTP Basic authentication, as an authorization token and as
   the password of the login form, in any other request. Used that way, the session of an
   impersonation would act as the user outside the marked session and therefore outside points 3
   and 4. The record of every impersonation names its session token: a request that presents that
   token outside the impersonated session (as its session, in an `Authorization` header or in a
   request parameter) is refused with HTTP 401 and ends the impersonation (a request with more than
   256 parameter values in the shape of a session id is not examined but refused with HTTP 503
   while an impersonation is recorded; this refusal alone is logged at info level, so that an
   anonymous client cannot fill the log). Request parameters are the query, a form and a JSON or
   form-encoded body, as ownCloud hands them to its controllers. The body of a WebDAV request
   (`remote.php`, `public.php`) and a `PUT` body of any other type are files and are not decoded:
   of such requests the query and a form that PHP itself has parsed are examined, and their
   credentials travel in a header or in the session. An
   impersonated session that is not bound to
   the token it was started with anymore (e.g. its id changed) or whose record is gone is ended on
   its next request; and every end – by logout, by the checks of point 4 or by the background job –
   revokes the token by its id. Requests outside an impersonation are not affected otherwise; while
   an impersonation is recorded, the credentials they present are looked up (and a request is
   refused with HTTP 503 if that lookup fails).

The impersonator's session token is parked under a random secret that exists only in the encrypted
PHP session (never sent to the browser); it keeps its encrypted login password – if the session had
one – so the restored session stays password-bound (a later password change still invalidates it).

## Accepted risks and design decisions

* **Inherent power** – while impersonating, the impersonator can do everything the user can (read and
  change files, create shares and public links, change the e-mail address). Such actions persist and
  are attributed to the user in other apps' logs. Only grant the right to people you trust with the
  accounts concerned.
* **Second factor** – impersonation does not ask for the user's second factor.
* **Administrators impersonating administrators** is allowed (an administrator can reset another
  administrator's password anyway). Group admins can never impersonate administrators.
* **Group admins impersonating group admins** is refused by default. A member who is a group admin
  may administer other groups, so the impersonator would act on groups that were not delegated to
  them. The option "Allow group admins to impersonate members who are group admins themselves"
  accepts this.
* **What a group admin who may impersonate is told** – the users page receives the ids of the
  members of their groups whom they cannot impersonate (administrators and, unless the option above
  is set, group admins), so that it shows no icon for them. Users who cannot impersonate and
  impersonated sessions get an empty answer.
* **Sessions without a login password** (e.g. single sign-on) – the impersonator's password cannot
  be re-checked, and the session restored afterwards is not bound to one. Such impersonations end by
  the maximum duration; do not set it to `0` on instances with such logins.
* **Idle timeout** – if the session of an impersonation expires, it is ended and logged by the
  background job (point 6), with a delay; the parked token cannot be used (its secret was only in the
  session) and is removed by core's token cleanup. If the job and the session end the same
  impersonation at the same moment, the end event can be dispatched twice.
* **The credential cleanup hits the owner's credentials too** (point 7) – those that appear between
  the start of an impersonation and the first run of the cleanup after its end (for a lost session:
  the run of the background job that ends it). A cleanup that has to be retried does not reach
  credentials that appeared later. The owner is told and can create them again. ownCloud lists at
  most a limited number of tokens per user (1000): for an account with that many the cleanup may
  miss one, and logs an error.
* **The deny-list is a list** (point 3) – what other installed apps offer is only covered by the
  prefixes you add.
* **Disabling the app** during an active impersonation leaves that session on the impersonated
  identity until its next logout, without any of the controls above. End the active impersonations
  first: `occ impersonate:active --end`.
* **Session values of other apps** – five identity-bound values are moved out of the session
  (point 2); whatever else ownCloud or other apps keep in the session stays, in both directions. The
  encryption state of the impersonator's session stays active during the impersonation (needed for
  the master key mode) and is restored exactly afterwards; with per-user keys the impersonator's key
  is in the impersonated session.
* **External storage credentials of the user** – core lets the logged-in user edit their personal
  external storages; an impersonator could point a storage with saved credentials to another host.
  This is a core behaviour that impersonation makes reachable; restrict personal external storages
  (`files_external` "Allow users to mount external storage") if this matters.

## Hardening checklist for administrators

* Keep impersonation to administrators unless group admins really need it; enable `allow_subadmins`
  only if you use group admins, and leave group admins as targets off.
* Install the app read-only for the web server (README section 2) and keep
  `integrity.ignore.missing.app.signature` limited to this app.
* Keep `max_duration_minutes` as short as helpdesk work allows (default 60).
* Run the background jobs with system cron (`occ background:cron`), so that lost impersonations are
  ended and cleaned up in time.
* List the installed apps that issue credentials (tokens, keys, grants) or change e-mail address or
  recovery settings of an account, and add their path prefixes to `forbidden_prefixes`.
* Keep the ownCloud log level at warning (2) or lower so that impersonations are recorded, and ship
  the log to a place the impersonators cannot change.
* Watch for `Refused …`, `… refused: …`, `Ending impersonation …`, `… ended without a logout …`,
  `… is not part of the impersonated session …` and `Revoked …` /
  `Removed the URL signing key …` log lines, or consume the three events.
* Keep the notifications app enabled, so that account owners learn about revoked credentials.
* Before you disable or remove the app: `occ impersonate:active --end`.
* Use HTTPS, and keep `session_lifetime` / `session_keepalive` short.

## Security review

Version 1.0.0 was reviewed before its release: a static audit of the inherited code (four independent
reviewers, adversarial verification, live reproduction on ownCloud 11.1.0), followed by fixes and an
independent review of the fixes with live reproduction. The findings and their fixes are listed in
[CHANGELOG.md](CHANGELOG.md) (1.0.0, "Security").

Version 1.0.1 is the result of a second, full source review of the plugin on 2026-11-27 (with
Anthropic's Mythos 5.2: several independent assessments, an independent review of each, a
consolidated report; advisory check of the dependencies). It found no vulnerability of critical or
high risk, one of medium risk (impersonations started without an interactive session) and fifteen of
low risk, mostly in failure paths, the audit trail, the scope of the deny-list, the documentation and
the build chain. The fixes were reviewed independently and tested on ownCloud 11.1.0; that review
found more weaknesses, which 1.0.0 has as well: the session id of an impersonation worked as a
credential outside the impersonated session and so outside its checks (point 8), a session token
could be left behind valid when the id of the session had changed, and a request with HTTP Basic
credentials could still start an impersonation through a session it had created (point 1). Every finding that can be
fixed within the plugin is fixed in 1.0.1 ([CHANGELOG.md](CHANGELOG.md), 1.0.1). What cannot be
decided from the plugin's code is stated above as it is: the deny-list is a list (point 3), and the
behaviour of ownCloud itself, of other apps and of a concrete installation was not part of the
review. An automated review is not a certification.

Version 1.0.2 is the result of the verification of these fixes on 2026-11-27: every finding was
compared with the code again and the tests were repeated on ownCloud 11.1.0 – also behind Apache
with URL rewriting and with server-side encryption (master key). The fixes held, with one defect:
while an impersonation was active, the check of point 8 changed how requests of everybody else
were handled (an upload through a public link was refused). 1.0.2 fixes that
([CHANGELOG.md](CHANGELOG.md), 1.0.2).

Version 1.0.3 adds translations into every language of ownCloud 11.1, updates the QA tools and fixes
how a refused impersonation is shown behind nginx (its error pages hide the reason); none of the
properties above changes. Before the release its changes were reviewed independently, and the
security checks ran on SQLite with PHP's built-in server, on MariaDB behind Apache with mod_php and
on PostgreSQL behind nginx with PHP-FPM ([CHANGELOG.md](CHANGELOG.md), 1.0.3).

`tests/e2e/security-checks.sh` checks the properties above on a live instance in CI.
