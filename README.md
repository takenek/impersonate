# Impersonate (`impersonate`) – log in as another user on ownCloud 11

[![CI](https://github.com/takenek/impersonate/actions/workflows/ci.yml/badge.svg)](https://github.com/takenek/impersonate/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/takenek/impersonate?sort=semver)](https://github.com/takenek/impersonate/releases/latest)
[![License](https://raw.githubusercontent.com/takenek/impersonate/main/.github/badges/license.svg)](LICENSE)

Impersonate lets ownCloud administrators – and, if allowed, group admins – log in as another user
for helpdesk work: see what the user sees, fix their configuration, act in legacy accounts. A new
column in the user management lists an icon next to every user that may be impersonated. A banner
shows whom you are impersonating; logging out returns you to your own session.

Created and maintained by **[Marek Królikowski (TaKeN)](https://github.com/takenek)**,
operating as **TaKeN.PL Usługi Informatyczne Marek Królikowski**.

This project is a maintained, security-hardened fork of the ownCloud app
[owncloud/impersonate](https://github.com/owncloud/impersonate) (archived), originally written by
Jörn Friedrich Dreyer, Sujith Haridasan and contributors (see [COPYRIGHT](COPYRIGHT) and
[AUTHORS.md](AUTHORS.md)). It is not affiliated with or endorsed by ownCloud GmbH.

Documentation: [SECURITY.md](SECURITY.md) · [CHANGELOG.md](CHANGELOG.md) · [COPYRIGHT](COPYRIGHT)

---

## 1. Requirements

| Component | Requirement |
|---|---|
| ownCloud | 11.x (tested: **11.1.0**) – classic web UI |
| PHP | **8.3** (ownCloud 11.1 runs only on PHP 8.3) |
| Database | any database supported by ownCloud (tested with SQLite, the app has no tables) |

Version 1.x does not support ownCloud 10. On ownCloud 10 use the original app 0.6.x.

## 2. Installation

1. Download `impersonate-1.0.0.tar.gz` and `impersonate-1.0.0.tar.gz.sha256` from the
   [latest release](https://github.com/takenek/impersonate/releases/latest) and verify the archive:

   ```bash
   sha256sum -c impersonate-1.0.0.tar.gz.sha256
   ```

   The release archive is built by CI from the signed tag `v1.0.0` (see [SECURITY.md](SECURITY.md),
   "Verifying a release").

2. Extract it into an app directory of your ownCloud (the archive contains the folder
   `impersonate/`), for example `apps-external` (it must be listed in `apps_paths` of `config.php`):

   ```bash
   sudo tar -xzf impersonate-1.0.0.tar.gz -C /var/www/owncloud/apps-external
   sudo chown -R www-data:www-data /var/www/owncloud/apps-external/impersonate
   ```

3. ownCloud 11 verifies code signatures. This app is not signed with an ownCloud certificate, so the
   integrity check reports `MISSING_SIGNATURE` for it, and the app installer (`occ market:install`,
   app updates from a tarball) refuses it. Allow the missing signature in `config.php`:

   ```php
   'integrity.ignore.missing.app.signature' => ['impersonate'],
   ```

4. Enable the app:

   ```bash
   sudo -u www-data php occ app:enable impersonate
   ```

5. Optional – group admins: ownCloud 11 disables the group admin feature by default. Group admins can
   only impersonate users if it is enabled in `config.php`:

   ```php
   'allow_subadmins' => true,
   ```

### Upgrade from the ownCloud app (0.x)

Disable nothing: replace the folder `impersonate` by the one from the archive (remove the old folder
first), then run `sudo -u www-data php occ upgrade`. The settings are kept.

### Uninstall

```bash
sudo -u www-data php occ app:disable impersonate
sudo -u www-data php occ config:app:delete impersonate impersonate_include_groups_list   # optional
```

and remove the folder.

## 3. Configuration

Admin settings → **User Authentication** → **Impersonate Settings**:

| Option | Who may impersonate |
|---|---|
| Only an administrator is allowed to impersonate users | administrators: any enabled user except themselves |
| Allow all group admins to impersonate users within the groups they are admins of | administrators, and group admins: enabled members of the groups they administer (never administrators) |
| Allow group admins of specific groups to impersonate the users within those groups | administrators, and group admins of the selected groups: enabled members of those groups (never administrators) |

The group admin options need `'allow_subadmins' => true` (section 2); the admin page shows a hint
when the feature is disabled. Users who never logged in cannot be impersonated (their file system is
set up by the first login).

## 4. Security

Impersonation is powerful by design: the impersonator acts with the full rights of the user,
including the user's files and shares, without the user's password or second factor. The app limits
what outlives an impersonation and records it:

* every start, end and refusal is logged (warning level, uids and remote address) and dispatched as
  the events `user.afterimpersonate` / `user.afterimpersonatelogout`;
* the impersonated user sees the session as "Impersonated by &lt;uid&gt;" in Personal → Security and
  can revoke it;
* the impersonator's login password and other identity-bound session data are never available to the
  impersonated session;
* app passwords, the URL signing key and OAuth2 grants cannot be obtained while impersonating;
* the impersonation is re-checked on every request and ends when the impersonator is disabled,
  deleted, loses the permission or changes the password;
* only the user's own "Log out" switches back; security logouts end the session.

Details, accepted risks and a hardening checklist: [SECURITY.md](SECURITY.md).
Report vulnerabilities privately: <https://github.com/takenek/impersonate/security/advisories/new>.

## 5. Development and tests

```bash
make build-dep js-templates      # node_modules + compiled Handlebars templates
make dist                        # build/impersonate-<version>.tar.gz (+ .sha256)
```

The tests need an ownCloud 11.1 installation; `tests/ci/install-owncloud.sh` installs a throw-away
instance (the official QA build, verified by SHA-256) with SQLite and deploys the app:

```bash
export OC_DIR=/tmp/oc ADMIN_PASSWORD=$(openssl rand -hex 12) USER_PASSWORD=$(openssl rand -hex 12)
tests/ci/install-owncloud.sh
cd $OC_DIR/apps/impersonate && php ../../lib/composer/bin/phpunit -c phpunit.xml --testsuite unit
php -S localhost:8080 -t $OC_DIR &                      # in another shell
BASE=http://localhost:8080 tests/e2e/setup-users.sh
BASE=http://localhost:8080 tests/e2e/e2e.sh             # HTTP end-to-end
BASE=http://localhost:8080 tests/e2e/security-checks.sh # security properties
```

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs PHPUnit, PHPStan, Phan, PHP-CS-Fixer,
a gitleaks secret scan, the HTTP end-to-end and security checks, the Behat API acceptance tests and a
headless browser test against ownCloud 11.1.0 on PHP 8.3, and builds and publishes the release
archive for signed tags.

## 6. Known limitations

* An impersonation that ends by an idle timeout of the session is not logged as ended (the start is).
* If the app is disabled while a session impersonates somebody, that session keeps the impersonated
  identity until it is logged out (the logout is then a normal logout).
* With per-user encryption keys (not master key) the files of the impersonated user cannot be
  decrypted while impersonating.

## 7. License

GNU Affero General Public License version 3 ([LICENSE](LICENSE)); additional attribution terms for
the material of this fork according to AGPLv3 section 7(b)/(c): [COPYRIGHT](COPYRIGHT).
