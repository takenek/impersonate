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
sha256sum -c impersonate-1.0.0.tar.gz.sha256

# the tag is signed by the release key
git clone https://github.com/takenek/impersonate.git && cd impersonate
git -c gpg.ssh.allowedSignersFile=.github/release-signers verify-tag v1.0.0

# the archive can be rebuilt from the tag (reproducible: same content, same checksum)
git checkout v1.0.0 && make dist && cat build/impersonate-1.0.0.tar.gz.sha256
```

The app is not signed with an ownCloud code signing certificate (only ownCloud can issue those), see
README section 2 for `integrity.ignore.missing.app.signature`.

## Security model

Impersonation gives the impersonator the complete identity of the impersonated user for the duration
of the session. The app is designed so that

1. **only authorized users can start it** – administrators (any enabled user except themselves) and,
   if configured and `allow_subadmins` is enabled, group admins (enabled, non-admin members of the
   groups they may impersonate in); the decision is made in one place (`lib/Policy.php`) and users who
   may not impersonate learn nothing about other accounts;
2. **nothing of the impersonator leaks into the impersonated session** – the impersonator's login
   name, the login password that core keeps for "Log-in credentials, save in session" external
   storages, app password and DAV markers are moved out of the session and restored afterwards; the
   session id and the CSRF token are rotated on every switch;
3. **nothing obtained during the impersonation outlives it** – app passwords, the URL signing key
   (pre-signed WebDAV URLs) and OAuth2 grants cannot be obtained while impersonating; as a backstop,
   passwordless app passwords of the user created during the impersonation are revoked and a signing
   key created during it is removed when it ends;
4. **it ends when the authorization ends** – it is re-checked on every request (after all
   authentication apps are loaded): it ends with a full logout when the impersonator is deleted,
   disabled, loses the permission, changes the password (checked like core does every
   `last_check_timeout` minutes) or the impersonator's parked session is revoked;
5. **only the user's own logout switches back** – a logout that core triggers for security reasons
   (revoked or invalid session, auth header mismatch, password reset) ends the session instead; the
   switch back requires the CSRF token of the logout link;
6. **it is visible and audited** – the impersonated user sees the session as
   "Impersonated by &lt;uid&gt;" and can revoke it; the impersonator's own session stays listed (and
   revocable) in their session list; every start, end and refusal is logged at warning level with the
   canonical uids and the remote address, and the events `user.afterimpersonate` and
   `user.afterimpersonatelogout` are dispatched (consumed e.g. by audit apps).

The impersonator's session token is parked under a random secret that exists only in the encrypted
PHP session (never sent to the browser); it keeps its encrypted login password so the restored
session stays password-bound (a later password change still invalidates it).

## Accepted risks and design decisions

* **Inherent power** – while impersonating, the impersonator can do everything the user can (read and
  change files, create shares and public links, change the e-mail address). Such actions persist and
  are attributed to the user in other apps' logs. Only grant the right to people you trust with the
  accounts concerned.
* **Second factor** – impersonation does not ask for the user's second factor.
* **Administrators impersonating administrators** is allowed (an administrator can reset another
  administrator's password anyway). Group admins can never impersonate administrators.
* **Group admins impersonating group admins** of the same group is allowed; ownCloud already lets a
  group admin reset the password of such a member.
* **Idle timeout** – if the session of an impersonation expires, the end is not logged; the parked
  token cannot be used (its secret was only in the session) and is removed by core's token cleanup.
* **Disabling the app** during an active impersonation leaves that session on the impersonated
  identity until its next logout.
* **External storage credentials of the user** – core lets the logged-in user edit their personal
  external storages; an impersonator could point a storage with saved credentials to another host.
  This is a core behaviour that impersonation makes reachable; restrict personal external storages
  (`files_external` "Allow users to mount external storage") if this matters.

## Hardening checklist for administrators

* Keep impersonation to administrators unless group admins really need it; enable `allow_subadmins`
  only if you use group admins.
* Keep the ownCloud log level at warning (2) or lower so that impersonations are recorded, and ship
  the log to a place the impersonators cannot change.
* Watch for `Refused …` and `Ending impersonation …` log lines.
* Use HTTPS, and keep `session_lifetime` / `session_keepalive` short.

## Security review

Version 1.0.0 was reviewed before its release: a static audit of the inherited code (four independent
reviewers, adversarial verification, live reproduction on ownCloud 11.1.0), followed by fixes and an
independent review of the fixes with live reproduction. The findings and their fixes are listed in
[CHANGELOG.md](CHANGELOG.md) (1.0.0, "Security"). `tests/e2e/security-checks.sh` checks the
properties above on a live instance in CI.
