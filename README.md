# Impersonate (`impersonate`) – log in as another user on ownCloud 11

[![CI](https://github.com/takenek/impersonate/actions/workflows/ci.yml/badge.svg)](https://github.com/takenek/impersonate/actions/workflows/ci.yml)
[![Release](https://raw.githubusercontent.com/takenek/impersonate/main/.github/badges/release-v1.0.2.svg)](https://github.com/takenek/impersonate/releases/latest)
[![License](https://raw.githubusercontent.com/takenek/impersonate/main/.github/badges/license.svg)](LICENSE)

Impersonate lets ownCloud administrators – and, if allowed, group admins – log in as another user
for helpdesk work: see what the user sees, fix their configuration, act in legacy accounts. A new
column in the user management lists an icon next to every user that may be impersonated; a click
asks for confirmation and switches the session. A banner shows whom you are impersonating; logging
out returns you to your own session.

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

1. Download `impersonate-1.0.2.tar.gz` and `impersonate-1.0.2.tar.gz.sha256` from the
   [latest release](https://github.com/takenek/impersonate/releases/latest) and verify the archive:

   ```bash
   sha256sum -c impersonate-1.0.2.tar.gz.sha256
   ```

   The release archive is built by CI from the signed tag `v1.0.2` (see [SECURITY.md](SECURITY.md),
   "Verifying a release"; the archive contains the SECURITY.md of its version).

2. Extract it into an app directory of your ownCloud (the archive contains the folder
   `impersonate/`), for example `apps-external` (it must be listed in `apps_paths` of `config.php`).
   The code of this app runs on every request of the instance, so the web server must be able to
   read it but **not to change it**: the files belong to `root` (or a deployment account), the web
   server's group may only read them. Replace `www-data` by the group of your web server:

   ```bash
   sudo tar -xzf impersonate-1.0.2.tar.gz -C /var/www/owncloud/apps-external
   sudo chown -R root:www-data /var/www/owncloud/apps-external/impersonate
   sudo chmod -R u=rwX,g=rX,o= /var/www/owncloud/apps-external/impersonate
   ```

   The app is installed and updated by hand as described here; it does not need a writable app
   directory.

3. ownCloud 11 verifies code signatures. This app is not signed with an ownCloud certificate, so the
   integrity check reports `MISSING_SIGNATURE` for it, and the app installer (`occ market:install`,
   app updates from a tarball) refuses it. Allow the missing signature in `config.php` for this app
   only (do not add other apps to the list on account of this one, and do not disable the integrity
   check):

   ```php
   'integrity.ignore.missing.app.signature' => ['impersonate'],
   ```

   ownCloud can therefore not tell you when the installed files were changed. The checksum and the
   signed tag are verified at installation; to check an installation later, compare it with the
   verified archive:

   ```bash
   mkdir /tmp/impersonate-check && tar -xzf impersonate-1.0.2.tar.gz -C /tmp/impersonate-check
   sudo diff -r /tmp/impersonate-check/impersonate /var/www/owncloud/apps-external/impersonate && echo unchanged
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

6. Make sure the background jobs of ownCloud run (system cron is recommended: `occ background:cron`).
   The app uses one to finish impersonations whose session was lost (section 4).

### Upgrade (from 1.0.x or from the ownCloud app 0.x)

Disable nothing: replace the folder `impersonate` by the one from the archive (remove the old folder
first, set the owner as in step 2), then run `sudo -u www-data php occ upgrade`. The settings are
kept. Read the "Upgrade notes" of the new version in [CHANGELOG.md](CHANGELOG.md) first: 1.0.1
changes behaviour (no start through the API, maximum duration, group admins as targets,
confirmation, background jobs).

### Uninstall

End the impersonations that are active first: a session that impersonates somebody while the app is
disabled keeps the impersonated identity without any of the controls of the app. The command also
takes the background job of the app off the job list.

```bash
sudo -u www-data php occ impersonate:active --end
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
| Allow group admins to impersonate members who are group admins themselves (off by default) | with one of the two group admin options: such members become possible targets. They may administer other groups, and the impersonating group admin would act with those rights as well |

The group admin options need `'allow_subadmins' => true` (section 2); the admin page shows a hint
when the feature is disabled. Users who never logged in cannot be impersonated (their file system is
set up by the first login). Every change of the page is stored by one request that the server
validates (only existing groups are kept); a group that is deleted leaves the list.

An impersonation can only be started in the web interface, from a browser session that was logged
in through the login form: a request that brings credentials of its own (HTTP Basic, an app
password, a token) is refused, and so is a session that such a request created.

Further settings (app config, set with `occ`):

| Setting | Default | Meaning |
|---|---|---|
| `max_duration_minutes` | `60` | An impersonation ends (with a logout) after this many minutes. `0` = no limit; a value that is not a whole number counts as the default |
| `allow_start_with_credentials` | `false` | `true`: an impersonation may also be started by a request that carries credentials (an `Authorization` header) or from a session such a request created. Only for instances where every request of a browser carries credentials (authentication by a proxy or by the web server): ownCloud does not ask such requests for the CSRF token, and their sessions are not the result of an interactive login |
| `forbidden_prefixes` | `[]` | JSON list of path prefixes as the router sees them (without `index.php`), e.g. `["/apps/someapp/"]`: requests below them are refused during an impersonation, in addition to the built-in list (section 4). Use it for installed apps that issue credentials or change how an account is recovered. The admin page shows the prefixes in use and names entries it ignores (anything that is not a plain path) |

```bash
sudo -u www-data php occ config:app:set impersonate max_duration_minutes --value=30
sudo -u www-data php occ config:app:set impersonate forbidden_prefixes --value='["/apps/someapp/"]'
sudo -u www-data php occ impersonate:active          # who impersonates whom right now
sudo -u www-data php occ impersonate:active --end    # end all of them at once
```

## 4. Security

Impersonation is powerful by design: the impersonator acts with the full rights of the user,
including the user's files and shares, without the user's password or second factor. The app limits
what outlives an impersonation and records it:

* an impersonation starts only from a browser session (the user interface asks for confirmation and
  names the account) and lasts at most `max_duration_minutes`;
* the session of an impersonation cannot be used anywhere else. ownCloud accepts the id of a session
  as a token of its user (as the password of HTTP Basic authentication, as an authorization token,
  as the password of the login form): a request that presents the session id of an impersonation
  outside that session is refused and ends the impersonation, and every end revokes the session
  token;
* every start, every end and every refusal is logged (warning level, uids, for requests the remote
  address; only the refusal of a request that is not examined, SECURITY.md point 8, at info level);
  the events `user.afterimpersonate` and `user.afterimpersonatelogout` (with the reason)
  are dispatched. An impersonation whose session just expires is ended and reported by a background
  job;
* the impersonated user sees the session as "Impersonated by &lt;uid&gt;" in Personal → Security and
  can revoke it;
* the impersonator's login password and other identity-bound session data are never available to the
  impersonated session;
* app passwords (`POST /settings/personal/authtokens`), the URL signing key
  (`/cloud/user/signing-key`), OAuth2 grants (`/apps/oauth2/`) and a login through the login form
  (`POST /login`) are refused while impersonating, and so is anything below the prefixes you add
  (section 3). Operations of other installed apps are not covered unless you add them. As a
  backstop, app passwords and sessions without a stored password and a URL signing key that appeared
  for the user during the impersonation are removed when it ends – also ones the account owner
  created in that time (possible after a login without a password, e.g. single sign-on); the owner
  gets a notification for each;
* the impersonation is re-checked on every request and ends when the impersonator is disabled or
  deleted, loses the permission, reaches the maximum duration, or changes the password (the password
  is re-checked for impersonations that were started from a session with a login password; others,
  e.g. single sign-on sessions, are bounded by the maximum duration). A request whose check cannot be
  completed is refused;
* only the user's own "Log out" switches back; security logouts end the session, and so does a
  switch that fails half-way.

Details, accepted risks and a hardening checklist: [SECURITY.md](SECURITY.md).
Report vulnerabilities privately: <https://github.com/takenek/impersonate/security/advisories/new>.

## 5. Development and tests

```bash
make build-dep js-templates      # node_modules + compiled Handlebars templates
make dist                        # build/impersonate-<version>.tar.gz (+ .sha256)
```

The tools are installed from lockfiles: `package-lock.json` (build), `vendor-bin/*/composer.lock`
(PHPStan, Phan, PHP-CS-Fixer, Behat) and `tests/ui/package-lock.json` (browser test).

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
npm ci --prefix tests/ui && (cd tests/ui && npx playwright-core install chromium)
BASE=http://localhost:8080 node tests/ui/ui-impersonate.js   # headless browser
BASE=http://localhost:8080 tests/e2e/encryption.sh      # last: enables server-side encryption
```

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs PHPUnit, PHPStan, Phan, PHP-CS-Fixer,
a gitleaks secret scan, the HTTP end-to-end and security checks, the Behat API acceptance tests, a
headless browser test and a check with server-side encryption against ownCloud 11.1.0 on PHP 8.3,
and builds and publishes the release archive for signed tags.

## 6. Known limitations

* An impersonation that ends by an idle timeout of the session is ended, cleaned up and logged by a
  background job, not at the moment the session expires: at the first run of the background jobs
  that is more than two minutes past the maximum duration, or – without a maximum duration – once
  ownCloud has removed the expired session. Without working background jobs it is not logged as
  ended at all (the start is).
* If the app is disabled while a session impersonates somebody, that session keeps the impersonated
  identity until it is logged out (the logout is then a normal logout). Run
  `occ impersonate:active --end` before you disable the app.
* Server-side encryption: the app is tested without encryption and with master-key encryption, which
  is what `occ encryption:enable` sets up on ownCloud 11.1. Per-user keys, which an instance that was
  upgraded from an older version may still use, are not tested: there the files of the impersonated
  user cannot be decrypted while impersonating, and the impersonator's key stays in the session
  during the impersonation. Test it in your encryption mode first.
* Group ids that contain the character `|` cannot be selected or removed in the admin page (the
  group picker of ownCloud uses it as a separator). The page shows them and keeps them in the list;
  change them with `occ config:app:set impersonate impersonate_include_groups_list`.
* While an impersonation is active, every request to the instance costs one or two additional token
  lookups (the check that the session token of the impersonation is not used elsewhere).
* The Polish translation is complete. In the other languages the texts that came with 1.0.0, 1.0.1
  and 1.0.2 (among them the confirmation before an impersonation starts and the notifications about
  revoked credentials) are not translated yet: they are shown in English.

## 7. Security review

The code was reviewed with Anthropic's Mythos 5.2 on 2026-11-27 (full source review of the plugin,
advisory check of its dependencies, remediation of every accepted finding that can be fixed within
the plugin in release 1.0.1, a verification of these fixes that led to release 1.0.2; see
[CHANGELOG.md](CHANGELOG.md) and [SECURITY.md](SECURITY.md)). The
review covered the code of this plugin only: ownCloud itself, other apps and the configuration of
your instance were not part of it. An automated review is not a certification: report anything it
missed as described in SECURITY.md.

## 8. License

GNU Affero General Public License version 3 ([LICENSE](LICENSE)); additional attribution terms for
the material of this fork according to AGPLv3 section 7(b)/(c): [COPYRIGHT](COPYRIGHT).
