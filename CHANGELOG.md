# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

## [Unreleased]

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
  (`/ocs/v1|v2.php/cloud/user/signing-key`) and OAuth2 grants (`/apps/oauth2/`). The paths are
  matched the way the router matches them. As a backstop, passwordless app passwords of the user
  created during the impersonation are revoked and a signing key created during it is removed when
  it ends.
- An active impersonation is re-checked on every request, after all authentication apps (e.g. LDAP
  group backends) are loaded, and ends with a full logout when the impersonator is deleted or
  disabled, loses the permission to impersonate the user, changes the password (checked every
  `last_check_timeout` minutes, like core does), or the impersonator's own session is revoked.
- Only the user's own logout (GET /logout with the CSRF token, while the impersonated session is
  valid) switches back to the impersonator. Security logouts (revoked or invalid session, auth header
  mismatch, password reset, ...) end the impersonation and log out.
- The session id and the CSRF token are rotated when the impersonation starts and ends; the old
  session id keeps no authenticated state, so requests still using it (e.g. queued on the session
  lock) see an anonymous session instead of logging the browser out. A switch that fails half-way is
  rolled back and logged out. The impersonator's session token keeps its stored password after
  switching back, so password changes still invalidate it.
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

[Unreleased]: https://github.com/takenek/impersonate/compare/v1.0.0...HEAD
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

