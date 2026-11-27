# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

## [Unreleased]

## [1.0.2] - 2026-11-27

Bug fix release. It fixes a defect of 1.0.1 that the verification of its fixes found, completes the
Polish translation and adds tests. Compared with 1.0.1 nothing changes in the configuration or in
the behaviour of an impersonation.

Upgrade from 1.0.1: replace the app folder (owned by `root`, see README section 2) and run
`occ upgrade`. From 1.0.0 or 0.x read the upgrade notes of 1.0.1 first (section 1.0.1 of
CHANGELOG.md, <https://github.com/takenek/impersonate/releases/tag/v1.0.1>): that release changed
behaviour.

### Fixed
- While somebody was impersonated, requests of everybody else were handled differently (1.0.1 only):
  an upload through a public link (WebDAV `PUT`) was refused with HTTP 503, the upload of a large
  JSON file through WebDAV could end with an out-of-memory error (HTTP 500), and a `PUT` request
  with another body to the OCS API was not answered as usual. The check that the session of an
  impersonation is not used as a credential asked ownCloud for the parameters of every request; it
  no longer does so for the body of a WebDAV request (`remote.php`, `public.php`) and for a `PUT`
  body whose content type names neither JSON nor a form. Of such requests the session, the
  `Authorization` header, the query and a form that PHP itself has parsed (a `POST` form) are
  examined as before. Found by the verification of the fixes of 1.0.1.
- The Polish translation is complete: 18 of 25 texts were shown in English, among them the
  confirmation before an impersonation starts, the error messages of a refused impersonation and
  most of the admin page. A unit test compares the texts in the code with the translation.
- The notification about a revoked credential is a sentence of its own for an app password, a
  session and the URL signing key, so that a translation covers the whole text (translated to
  Polish; the other languages show the English sentence). Before, an English label ("session …",
  "URL signing key") was put into the translated sentence. The event
  `user.impersonate.credentialrevoked` is unchanged.

### Changed
- Tests: the end-to-end checks send the blocked operations also without the front controller in the
  URL (as a web server with URL rewriting hands them to ownCloud) and compare the answers to
  requests of other users with and without an active impersonation; the browser test checks the
  confirmation in Polish and sets the language of its sessions; a new end-to-end check runs an
  impersonation with server-side encryption (master key) and compares the encryption state of the
  session before and after (finding IMP-08 of the security review).

## [1.0.1] - 2026-11-27

Security release. It fixes the findings of a full source review of the plugin (README section 7,
SECURITY.md "Security review"): no vulnerability of critical or high risk, one of medium risk
(IMP-01) and fifteen of low risk. The identifiers in brackets are those of the review.

Upgrade from 1.0.0: replace the app folder (owned by `root`, see README section 2) and run
`occ upgrade`.

### Upgrade notes – behaviour that changes
- An impersonation can only be started in the web interface. A request that is authenticated with
  HTTP Basic credentials or an app password is refused (HTTP 404, `cannotImpersonate`). Scripts that
  started impersonations that way have to log in through the login form and send the CSRF token.
- An impersonation ends after 60 minutes with a logout. Change it with
  `occ config:app:set impersonate max_duration_minutes --value=<minutes>` (`0` = no limit).
- Group admins can no longer impersonate members who are group admins themselves, unless the new
  option of the admin page allows it.
- The impersonate icon asks for confirmation before it switches.
- The background jobs of ownCloud have to run (cron) for impersonations whose session is lost to be
  ended, cleaned up and logged.

### Security
- An impersonation starts only from an interactive session: a request that carries credentials
  (HTTP Basic, app passwords, tokens), a session that such a request created, and a session without
  a session token of the current user are refused before anything is changed. Before, such an
  impersonation was not bound to the credential that started it (it skipped the periodic password
  check and survived a password change), and such a request did not need the CSRF token. Instances
  where every browser request carries credentials can allow such starts again with the app config
  `allow_start_with_credentials` (IMP-01, INF-10).
- The session of an impersonation can no longer be used as a credential. ownCloud accepts the id of
  a session as a token of its user (password of HTTP Basic authentication, authorization token,
  password of the login form); a request that presented the session id of an impersonation that way
  acted as the impersonated user outside the impersonated session, without the deny-list, the
  re-validation and the maximum duration. Such a request is now refused (HTTP 401) and ends the
  impersonation; the login form is refused inside an impersonated session; and sessions without a
  stored password that appeared for the user during the impersonation are revoked when it ends.
  Found by the review of the fixes; 1.0.0 is affected.
- Every end of an impersonation revokes its session token by its id, and an impersonated session
  that is not bound to that token anymore is ended. Before, a session whose id had changed (e.g. by
  a failed login attempt inside it) left a valid session token of the impersonated user behind.
  Found by the review of the fixes; 1.0.0 is affected.
- The per-request guard fails closed: the deny-list no longer depends on the re-validation of the
  impersonation, and a request of an impersonated session whose check fails (e.g. a user or group
  backend is down) is refused with HTTP 503 instead of being served unchecked. The guard is
  registered before anything else of the app, and a request whose path cannot be determined is
  refused while impersonating. Sessions that do not impersonate are not affected (IMP-02).
- The deny-list is compared without regard to letter case and to the entry point (`index.php`,
  `ocs/v1.php`, `ocs/v2.php`), and operators can add path prefixes of installed apps (app config
  `forbidden_prefixes`; the admin page shows them and names entries it ignores). The login form
  (`POST /login`) is on the list. The logout that returns to the impersonator can never be blocked.
  New end-to-end checks send every path form of the blocked operations (IMP-03, IMP-04).
- The credential cleanup (app passwords without a stored password and a URL signing key that
  appeared during the impersonation) and the end of an impersonation no longer depend on a logout:
  every impersonation has a server-side record, and a background job ends, cleans up and logs
  impersonations whose session expired or was lost. A cleanup that fails is retried, without
  reaching credentials that appeared after the impersonation had ended (IMP-03, IMP-06, IMP-10).
- Maximum duration of an impersonation (app config `max_duration_minutes`, default 60) and a
  confirmation that names the account before it starts (IMP-05).
- The event `user.afterimpersonatelogout` is dispatched for every end of an impersonation – also
  when the guard ends it or the background job does – with the new argument `reason`. The log names
  the observed condition instead of an assumed cause (IMP-06).
- Group admins cannot impersonate members who are group admins (who may administer other groups)
  unless the new option "Allow group admins to impersonate members who are group admins themselves"
  is set (IMP-07).
- Returning to the impersonator restores exactly the encryption state the session had before; a
  value the session got while impersonating does not stay (IMP-08).
- The account owner gets a notification for every credential the cleanup revoked, and the event
  `user.impersonate.credentialrevoked` is dispatched (IMP-09).
- Failures while switching are handled atomically: a switch back that fails half-way ends the
  impersonation and logs the session out; the session is marked as an impersonation before its user
  changes; a session value that cannot be stashed stops the start before anything is changed; a
  failing consumer of the start event no longer turns a successful switch into an error; a switch
  that failed is answered with HTTP 500 (`switchFailed`) instead of the 404 of a refusal, and the
  browser then reloads the page instead of offering a retry (IMP-10).
- The delegation policy is stored by one request to a new endpoint for administrators
  (`PUT /apps/impersonate/policy`) that validates it, keeps only existing groups and writes the
  values in an order that never leaves a broader delegation than the old or the new one. The admin
  page shows the stored policy after a failed save. A deleted group leaves the list (IMP-11).
- The account to impersonate is the one the icon was created for, read without type conversion; it
  is never derived from the text shown in the row (IMP-12).
- SECURITY.md and README state the guarantees as the code gives them (scope of the deny-list,
  password re-check, audit trail); SECURITY.md is part of the release archive (IMP-13).
- The release job checks that the tree it builds is the commit of the verified tag (and the commit
  the run was started for) and never replaces a published archive: a second run compares the
  published files with the ones it built and fails if they differ (IMP-14).
- The QA tools of CI are installed from lockfiles (`vendor-bin/*/composer.lock`, the dependency on a
  development branch is pinned to a commit) and the browser test library from
  `tests/ui/package-lock.json`; Dependabot watches all of them (IMP-15).
- Installation guide: the app files belong to `root` and are read-only for the web server; the
  signature exception stays limited to this app (IMP-16).

### Added
- `occ impersonate:active [--end]` lists the active impersonations or ends all of them, e.g. before
  the app is disabled; with `--end` the background job of the app is taken off the job list (INF-02).

### Changed
- The release archive has the same file modes whatever the umask of the builder is (`make dist`), so
  that it can be rebuilt from the tag with the same checksum everywhere.

### Fixed
- The banner showed no user name in Danish, Austrian German and Uyghur (wrong placeholder in the
  translation; the Uyghur text is shown in English until it is translated again). A unit test
  compares the placeholders of all translations with the source (INF-05).
- The secret scan control of CI only accepts the expected finding, not any failure of the scanner
  (INF-07).
- The session dump helper of the tests prints values of listed keys only and nothing about
  passwords (INF-04).

## [1.0.0] - 2026-11-26

First release of this fork (<https://github.com/takenek/impersonate>), maintained by Marek
Królikowski (TaKeN). Based on the archived ownCloud app owncloud/impersonate 0.7.0.

Requires ownCloud 11 (tested with 11.1.0) and PHP 8.3 (ownCloud 11.1 runs only on PHP 8.3).
ownCloud 10 is not supported. Upgrade from 0.x: replace the app folder and run `occ upgrade`.

### Security
- The impersonator's identity-bound session data (login name, the login password that core keeps for
  "Log-in credentials, save in session" external storages, app password, DAV markers) is no longer
  available to the impersonated session. Previously the impersonator's password was sent to external
  storages of the impersonated user.
- Credentials that would outlive the impersonation can no longer be obtained while impersonating:
  app passwords (`POST /settings/personal/authtokens`), the URL signing key for pre-signed WebDAV URLs
  (`/ocs/v1|v2.php/cloud/user/signing-key`) and OAuth2 grants (`/apps/oauth2/`). The request paths
  are normalized before they are compared (repeated slashes, URL encoding, trailing slash). As a
  backstop, passwordless app passwords of the user created during the impersonation are revoked and
  a signing key created during it is removed when it ends by a logout (1.0.1: in every case, see
  above for the scope of this list).
- An active impersonation is re-checked on every request, after all authentication apps (e.g. LDAP
  group backends) are loaded, and ends with a full logout when the impersonator is deleted or
  disabled, loses the permission to impersonate the user, changes the password (checked every
  `last_check_timeout` minutes, like core does, for impersonations started from a session with a
  stored login password), or the impersonator's own session is revoked.
- Only the user's own logout (GET /logout with the CSRF token, while the impersonated session is
  valid) switches back to the impersonator. Security logouts (revoked or invalid session, auth header
  mismatch, password reset, ...) end the impersonation and log out.
- The session id and the CSRF token are rotated when the impersonation starts and ends; the old
  session id keeps no authenticated state, so requests still using it (e.g. queued on the session
  lock) see an anonymous session instead of logging the browser out. A switch that fails half-way is
  rolled back and logged out. The impersonator's session token keeps its stored password (if it had
  one) after switching back, so password changes still invalidate it.
- The impersonated user's session is listed as "Impersonated by <uid>" in their session list.
- Users can no longer impersonate themselves or disabled users.
- The server now honours "Only an administrator is allowed to impersonate users" even if an old group
  list is still stored.
- No details about other accounts are revealed to users who are not allowed to impersonate, and the
  delegation policy is only sent to administrators and allowed group admins.
- Impersonation start, end and every refusal are logged at warning level with the canonical user ids
  and the remote address; the raw request parameter is no longer logged.
- Removed two routes without a working controller (`POST /apps/impersonate/logout`,
  `POST /apps/impersonate/settings/impersonatetemplate`) that produced HTTP 500 errors and error log
  entries for anonymous requests.
- `appinfo/app.php` is guarded so that an error can not break other requests of the instance.

### Changed
- ownCloud 11.1 support: the group admin options respect the `allow_subadmins` system config
  (disabled by default in ownCloud 11) and the admin panel shows a hint when it is disabled.
- Invalid values of `impersonate_include_groups_list` no longer break the "User Authentication" admin
  settings section (PHP 8 TypeError).
- The impersonate icon is only shown where the server allows impersonation (not for the user
  themselves, disabled users, users who never logged in, administrators for group admins, or group
  admins outside the configured groups); a second click while the request is pending is ignored.
- The impersonation banner link is clickable again, the markup is valid and user names are no longer
  double escaped; the column header and the icon tooltip are translatable.
- Uses `OCP\IConfig::getAppValue()` instead of the deprecated `OCP\IAppConfig::getValue()`.
- The templates are compiled with handlebars 4.7.10, the runtime version of ownCloud 11.1; the
  lockfile fetches from the npm registry over HTTPS only.
- `make dist` builds a reproducible `build/impersonate-<version>.tar.gz` (+ `.sha256`) whose folder is
  named after the app id (required by the ownCloud 11.1 installer); signing uses an optional
  `SIGN_CMD` because `occ integrity:sign-app` was removed in ownCloud 11.
- New CI: PHPUnit, PHPStan, Phan (now including `controller/`), PHP-CS-Fixer, gitleaks, HTTP
  end-to-end and security checks, Behat API acceptance tests and a headless browser test against
  ownCloud 11.1.0; signed release tags; release archives built by CI.
- Unit tests rewritten; acceptance test fixes and new scenarios for ownCloud 11.
- New maintainer, project URLs, COPYRIGHT and SECURITY.md.

## [0.7.0] - 2026-03-09 (owncloud/impersonate, unreleased upstream)

### Changed
- Requires ownCloud 11 and PHP 8.3 ([#251](https://github.com/owncloud/impersonate/pull/251),
  [#254](https://github.com/owncloud/impersonate/pull/254)).

## [0.6.1] - 2026-02-16

### Fixed
- [#245](https://github.com/owncloud/impersonate/pull/245) - subadmins only impersonate members of their groups

## [0.6.0] - 2023-12-14

### Added
- [#238](https://github.com/owncloud/impersonate/pull/238) - feature:remove enable only for specific groups

### Fixed
- [#236](https://github.com/owncloud/impersonate/pull/236) - fix: group admins can impersonate again


## [0.5.3] - 2023-07-27

### Changed

- [#231](https://github.com/owncloud/impersonate/pull/231) - [full-ci] Adjust for Symfony5
- Minimum core version 10.11, minimum php version 7.4
- Dependencies updated

## [0.5.2] - 2022-09-19

### Added

- [#202](https://github.com/owncloud/impersonate/pull/202) - Restrict impersonation to users allowed to use the app

### Fixed 

- [#207](https://github.com/owncloud/impersonate/pull/207) - Fix impersonate include groups list
- [#208](https://github.com/owncloud/impersonate/pull/208) - Allow impersonation if the target is in at least one of the allowed groups
- [#209](https://github.com/owncloud/impersonate/pull/209) - Adjust doc link
- [#210](https://github.com/owncloud/impersonate/pull/210) - If Impersonate gets configured, you cant get back to state "unconfigured" (default)
- Library updates

## [0.5.1] - 2022-01-14

### Fixed

- Fix encryption issues after the impersonator logs out - [#189](https://github.com/owncloud/impersonate/issues/189)

## [0.5.0] - 2019-03-05

### Added

- Add option for all group admins to impersonate their group members - [#134](https://github.com/owncloud/impersonate/issues/134)

## [0.4.0] - 2018-12-07

### Changed

- Set max version to 10 because core platform is switching to Semver

## [0.3.0] - 2018-11-08

### Added

- PHP 7.2 support - [#115](https://github.com/owncloud/impersonate/pull/115)
- Added Symfony event for impersonate action - [#109](https://github.com/owncloud/impersonate/pull/109)

### Changed

- Set max version to 10.1 because core is switching to semver - [#105](https://github.com/owncloud/impersonate/pull/105)

### Fixes

- Fix impersonate icon not displaying in some scenarios - [#114](https://github.com/owncloud/impersonate/pull/114)
- Don't break when a non-existing group is mentionned in the config - [#119](https://github.com/owncloud/impersonate/pull/119)

## [0.2.0] - 2018-04-17

### Changed

- Group admins can only impersonate members of the same group [#99](https://github.com/owncloud/impersonate/pull/99)

## [0.1.2] - 2017-12-07

### Changed

- Moved impersonate Settings into User Authentication Section in Admin Panel [#54](https://github.com/owncloud/impersonate/pull/54)
- View default app when impersonating a user [#88](https://github.com/owncloud/impersonate/pull/88)
- Use precompiled handlebars for frontend templates [#42](https://github.com/owncloud/impersonate/pull/42)
- Use core hooks for logout of impersonated users [#68](https://github.com/owncloud/impersonate/pull/68)

### Fixed
- Impersonate not working with 10.0.4 [#80](https://github.com/owncloud/impersonate/pull/80)


## [0.1.1] - 2017-11-13

### Changed

- Replace Phony target all with dist in Makefile - [#65](https://github.com/owncloud/impersonate/issues/65)
- Change screenshot, fix indentation in app info - [#61](https://github.com/owncloud/impersonate/issues/61)

### Fixed

- Prevent further level impersonation - [#63](https://github.com/owncloud/impersonate/issues/63)
- Clear session when impersonation does not happen - [#62](https://github.com/owncloud/impersonate/issues/62)
- Restrict impersonate to admin user from subadmin user - [#49](https://github.com/owncloud/impersonate/issues/49)
- Minor code cleanup - [#46](https://github.com/owncloud/impersonate/issues/46)

## [0.1.0] - 2017-05-31

### Added

- Add screenshot file - [#40](https://github.com/owncloud/impersonate/issues/40)
- Changing the order of signing the app - [#39](https://github.com/owncloud/impersonate/issues/39)
- Make logged in message permanent in users page - [#34](https://github.com/owncloud/impersonate/issues/34)
- Make loglevel messages from warning to info - [#31](https://github.com/owncloud/impersonate/issues/31)
- Makefile for impersonate app. - [#28](https://github.com/owncloud/impersonate/issues/28)
- User who hasn't logged in yet cannot be impersonated - [#27](https://github.com/owncloud/impersonate/issues/27)
- Upgrading the version from 0.0.5 to 0.1.0 - [#26](https://github.com/owncloud/impersonate/issues/26)
- Improve impersonate app with changes - [#16](https://github.com/owncloud/impersonate/issues/16)

### Changed

- Rename subadmins to Group admins - [#33](https://github.com/owncloud/impersonate/issues/33)
- Move location of keys to $(HOME)/.owncloud/certificates - [#30](https://github.com/owncloud/impersonate/issues/30)
- Adjust travis PHP versions - [#19](https://github.com/owncloud/impersonate/issues/19)

### Fixed

- Fix the user page issue - [#35](https://github.com/owncloud/impersonate/issues/35)
- This commit fixes the issues below: - [#24](https://github.com/owncloud/impersonate/issues/24)


## Old Log

### Added

owncloud-impersonate (0.0.3)
* use eventdispatcher for js injection to users page, requires oc9

owncloud-impersonate (0.0.2)
* add action to userlist instead of input field in admin settings

owncloud-impersonate (0.0.1)
* First release

[Unreleased]: https://github.com/takenek/impersonate/compare/v1.0.2...HEAD
[1.0.2]: https://github.com/takenek/impersonate/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/takenek/impersonate/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/takenek/impersonate/releases/tag/v1.0.0
[0.7.0]: https://github.com/owncloud/impersonate/compare/v0.6.1...8b137cc
[0.6.1]: https://github.com/owncloud/impersonate/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/owncloud/impersonate/compare/v0.5.3...v0.6.0
[0.5.3]: https://github.com/owncloud/impersonate/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/owncloud/impersonate/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/owncloud/impersonate/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/owncloud/impersonate/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/owncloud/impersonate/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/owncloud/impersonate/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/owncloud/impersonate/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/owncloud/impersonate/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/owncloud/impersonate/compare/v0.1.0...v0.1.1

