# Impersonate (`impersonate`) – log in as another user on ownCloud 11

[![CI](https://github.com/takenek/impersonate/actions/workflows/ci.yml/badge.svg)](https://github.com/takenek/impersonate/actions/workflows/ci.yml)
[![Release](https://raw.githubusercontent.com/takenek/impersonate/main/.github/badges/release-v1.0.4.svg)](https://github.com/takenek/impersonate/releases/latest)
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
| Database | any database supported by ownCloud; the app has no tables (tested: SQLite, MariaDB 11.8, PostgreSQL 17) |
| Web server | any setup ownCloud supports (tested: Apache 2.4 with mod_php, nginx 1.26 with PHP-FPM as the ownCloud documentation configures it; CI uses PHP's built-in server). PHP must start with a fresh state for every request (PHP-FPM, mod_php, CGI/FastCGI): long-running worker modes are not supported |
| Sessions | a session handler that locks the session while a request uses it (PHP's default file handler does; for Redis switch on `redis.session.locking_enabled`, which is off by default; for Memcached keep `memcached.sess_locking` on) |
| Languages | the 115 languages and language variants of ownCloud 11.1 (section 6) |

Version 1.x does not support ownCloud 10. On ownCloud 10 use the original app 0.6.x.

## 2. Installation

1. Download `impersonate-1.0.4.tar.gz` and `impersonate-1.0.4.tar.gz.sha256` from the
   [latest release](https://github.com/takenek/impersonate/releases/latest) and verify the archive:

   ```bash
   sha256sum -c impersonate-1.0.4.tar.gz.sha256
   ```

   The release archive is built by CI from the signed tag `v1.0.4` (see [SECURITY.md](SECURITY.md),
   "Verifying a release"; the archive contains the SECURITY.md of its version).

2. Extract it into an app directory of your ownCloud (the archive contains the folder
   `impersonate/`), for example `apps-external` (it must be listed in `apps_paths` of `config.php`).
   The code of this app runs on every request of the instance, so the web server must be able to
   read it but **not to change it**: the files belong to `root` (or a deployment account), the web
   server's group may only read them. Replace `www-data` by the group of your web server:

   ```bash
   sudo tar -xzf impersonate-1.0.4.tar.gz -C /var/www/owncloud/apps-external
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
   CHECK=$(mktemp -d) && tar -xzf impersonate-1.0.4.tar.gz -C "$CHECK" \
     && sudo diff -r "$CHECK/impersonate" /var/www/owncloud/apps-external/impersonate && echo unchanged
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

Read the "Upgrade notes" of the versions between yours and the new one in
[CHANGELOG.md](CHANGELOG.md) first: 1.0.1 changes behaviour (no start through the API, maximum
duration, group admins as targets, confirmation, background jobs); 1.0.2 and 1.0.3 change neither
the configuration nor the behaviour; 1.0.4 changes the exit status of `occ impersonate:active --end`
and the behaviour in failure and edge cases (its upgrade notes). Disable nothing: the settings are
kept. Run the commands in one shell, in the folder that holds the archive of the new version;
replace `/var/www/owncloud` and `www-data` by the folder of your ownCloud and the user of your web
server.

1. Find the folder of the app and the installed version:

   ```bash
   OCC="sudo -u www-data php /var/www/owncloud/occ"
   APPDIR=$($OCC app:getpath impersonate)
   echo "$APPDIR"                       # e.g. /var/www/owncloud/apps-external/impersonate
   $OCC app:list impersonate            # Version: 1.0.3
   ```

2. Download and verify the archive of the new version (section 2, step 1).

3. Block new impersonations and end the ones that are active. While the folder is replaced,
   ownCloud does not load the app, so an impersonated session would be without its checks for that
   moment. The installed version runs the command, so what it can do depends on that version:

   ```bash
   $OCC impersonate:active --end --block && echo "nothing is active"   # installed 1.0.4 or later
   ```

   Continue only if it prints `nothing is active`: the exit status is 0 only when no impersonation
   is active and no cleanup is still open afterwards; stop on any other status (1: an impersonation
   could not be ended, 3: a cleanup, possibly the revocation of a session token, is still open – see
   the ownCloud log and run the command again later). `--block` keeps new impersonations from
   starting until `--unblock` (step 5). The command lists every record that still waits for its
   cleanup (`record active_<id>: … impersonated …, ended …, session token …`). The cleanup of a user
   that cannot be loaded (deleted, or its user backend is gone) stays open for seven days after the
   end; if you know that the sessions of that user are gone, you can remove such a record yourself:
   `$OCC config:app:delete impersonate active_<id>`.

   Versions 1.0.1 to 1.0.3 have no `--block`, and only `--end` reports an open cleanup (not in its
   exit status): run `$OCC impersonate:active --end` twice and continue only if the second run
   prints nothing but `No active impersonations.`. These versions cannot block new impersonations:
   ask the administrators not to start any until step 5. The app 0.x and 1.0.0 have no such
   command: ask the impersonating administrators to log out instead.

4. Replace the folder and keep the old one as a backup outside the app folders of ownCloud (ownCloud
   must not find two copies of the app). Name the backup after the installed version; it must not
   exist yet:

   ```bash
   sudo mv "$APPDIR" /root/impersonate-1.0.3-backup
   sudo tar -xzf impersonate-1.0.4.tar.gz -C "$(dirname "$APPDIR")"
   sudo chown -R root:www-data "$APPDIR"
   sudo chmod -R u=rwX,g=rX,o= "$APPDIR"
   ```

   Reload PHP-FPM or Apache now (for example `sudo systemctl reload php8.3-fpm` or
   `sudo apachectl graceful`): PHP's opcache checks each file separately, at most every
   `opcache.revalidate_freq` seconds (with `opcache.validate_timestamps=0` never), so until then a
   request can run files of the old and of the new version together.

5. Run the upgrade, check the result and, once it says `unchanged`, allow new impersonations again:

   ```bash
   $OCC upgrade
   $OCC app:list impersonate            # Version: 1.0.4
   CHECK=$(mktemp -d) && tar -xzf impersonate-1.0.4.tar.gz -C "$CHECK" \
     && sudo diff -r "$CHECK/impersonate" "$APPDIR" && echo unchanged
   $OCC impersonate:active --unblock    # the command of the app works; impersonations may start
   ```

   When only the last number of the version changes (1.0.3 to 1.0.4), ownCloud takes the new
   version over by itself at the next request or `occ` command, so `occ upgrade` may answer
   "ownCloud is already latest version" (exit status 3): that is fine. A version whose first or
   second number changes needs `occ upgrade`. Do not switch on the maintenance mode for the upgrade
   of the app; if it is on, switch it off afterwards with `$OCC maintenance:mode --off`: when only
   the last number changes, `occ upgrade` in maintenance mode only answers that ownCloud is in
   maintenance mode (exit status 2, nothing is left to upgrade), and when the first or second number
   changes it runs but leaves the maintenance mode on.

6. To go back to the backup (only between versions whose first two numbers are the same, e.g. from
   1.0.4 to 1.0.3), block and end the impersonations as in step 3 first, then:

   ```bash
   sudo mv "$APPDIR" /root/impersonate-1.0.4-removed
   sudo mv /root/impersonate-1.0.3-backup "$APPDIR"
   # reload PHP-FPM or Apache as in step 4
   $OCC upgrade                         # "ownCloud is already latest version"
   $OCC app:list impersonate            # Version: 1.0.3
   ```

   `occ app:list` shows the version that ownCloud has registered, which the first `occ` command
   after the replacement of the folder updates: run `occ upgrade` before it, as in step 5. Then
   allow new impersonations again: `$OCC impersonate:active --unblock` (1.0.4 and later); a version
   before 1.0.4 does not know the block, remove it instead, so that it does not come back with the
   next upgrade: `$OCC config:app:delete impersonate starts_blocked`. Remove the backup once the
   version you want works.

### Uninstall

Block new impersonations and end the ones that are active first: a session that impersonates
somebody while the app is disabled keeps the impersonated identity without any of the controls of
the app. Continue only if the first command ends with exit status 0 (see step 3 of the upgrade); it
also takes the background job of the app off the job list.

```bash
sudo -u www-data php occ impersonate:active --end --block && echo "nothing is active"
sudo -u www-data php occ app:disable impersonate
sudo -u www-data php occ config:app:delete impersonate starts_blocked                    # the block
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

The app must be enabled for everybody (`occ app:enable impersonate`): its checks run for every
request only if ownCloud loads it for every request. ownCloud does not enable an authentication app
for groups only; should the configuration say so anyway, no impersonation starts (the log and
`occ impersonate:active` say why).

The group admin options need `'allow_subadmins' => true` (section 2); the admin page shows a hint
when the feature is disabled. Users who never logged in cannot be impersonated (their file system is
set up by the first login). Every change of the page is stored by one request that the server
validates (only existing groups are kept); a group that is deleted leaves the list, and the option
"Allow group admins to impersonate members who are group admins themselves" is switched off if it
was given for a list with that group (save the page again to keep it; the log says so).

An impersonation can only be started in the web interface, from a browser session that was logged
in through the login form: a request that brings credentials of its own (HTTP Basic, an app
password, a token) is refused, and so is a session that such a request created.

Further settings (app config, set with `occ`):

| Setting | Default | Meaning |
|---|---|---|
| `max_duration_minutes` | `60` | An impersonation ends (with a logout) after this many minutes. Exactly `0` = no limit; any other value that is not a whole number counts as the default |
| `allow_start_with_credentials` | `false` | `true`: an impersonation may also be started by a request that carries credentials (an `Authorization` header) or from a session such a request created. Only for instances where every request of a browser carries credentials (authentication by a proxy or by the web server): ownCloud does not ask such requests for the CSRF token (the app does: the start still needs the CSRF token of the page), and their sessions are not the result of an interactive login |
| `forbidden_prefixes` | `[]` | JSON list of path prefixes as the router sees them (without `index.php`), e.g. `["/apps/someapp/"]`: requests below them are refused during an impersonation, in addition to the built-in list (section 4). Use it for installed apps that issue credentials or change how an account is recovered. The admin page shows the prefixes in use and names entries it ignores (anything that is not a plain path) |
| `starts_blocked` | – | `true` while new impersonations are blocked for maintenance; set and removed by `occ impersonate:active --block` / `--unblock` |

```bash
sudo -u www-data php occ config:app:set impersonate max_duration_minutes --value=30
sudo -u www-data php occ config:app:set impersonate forbidden_prefixes --value='["/apps/someapp/"]'
sudo -u www-data php occ impersonate:active          # who impersonates whom right now
sudo -u www-data php occ impersonate:active --end    # end all of them at once
sudo -u www-data php occ impersonate:active --block  # no new impersonation until --unblock
```

`occ impersonate:active` also reports how many impersonations still wait for their cleanup, and for
how many of them the session token is not yet known to be revoked. With `--end` its exit status is 0 only when afterwards
nothing is active and no cleanup is open; 1 when an impersonation could not be ended (for example
because its user cannot be loaded), 3 when a cleanup is still open (the background job retries it),
2 for `--block` together with `--unblock`.

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
  e.g. single sign-on sessions, are bounded by the maximum duration). The request during which it
  ends is refused (a logout request, `/logout`, is not), and so is a request whose check cannot be
  completed;
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
instance (the official QA build, verified by SHA-256) with SQLite – or with MySQL/MariaDB or
PostgreSQL: `OC_DB_TYPE=mysql|pgsql` with `OC_DB_NAME`, `OC_DB_USER`, `OC_DB_PASSWORD`, `OC_DB_HOST`
and an empty database – and deploys the app:

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

Behind a web server that runs PHP as another user, set `PHP_AS="sudo -u www-data"` and the session
directory of the web server (`SESSION_DIR`); behind nginx with the error pages of the ownCloud
configuration set `ERROR_PAGES_REPLACED=1` (the body of a refusal is then the error page that nginx
serves instead of the app's answer; the status is still checked). `UI_LANGS` (comma-separated locale
codes) chooses the languages in which the browser test checks the confirmation and the admin section.

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
  `occ impersonate:active --end --block` before you disable the app, and continue only on exit
  status 0. The block stays in the configuration: when you enable the app again, run
  `occ impersonate:active --unblock`.
* If the app cannot build its request guard (for example after an update of ownCloud that changes
  something the app relies on) while an impersonation whose session token may still be valid is
  recorded, every request to the instance is refused with HTTP 503 and an error is logged: the
  guard cannot tell whether a request presents that token. Fix the cause; before you disable the app
  instead, run `occ impersonate:active --end` if it still works (the recorded token would work
  without the app's checks). No impersonation starts while the guard is not active.
* Server-side encryption: the app is tested without encryption and with master-key encryption, which
  is what `occ encryption:enable` sets up on ownCloud 11.1. Per-user keys, which an instance that was
  upgraded from an older version may still use, are not tested: there the files of the impersonated
  user cannot be decrypted while impersonating, and the impersonator's key stays in the session
  during the impersonation. Test it in your encryption mode first.
* Group ids that contain the character `|` cannot be selected or removed in the admin page (the
  group picker of ownCloud uses it as a separator). The page shows them and keeps them in the list;
  change them with `occ config:app:set impersonate impersonate_include_groups_list`.
* While an impersonation is recorded – until it has ended and its session token is known to be
  revoked – the credentials and up to 256 request values of every request to the instance that have
  the shape of a session id are looked up as tokens (the check that the session token of an
  impersonation is not used elsewhere); a request with more such values is refused with HTTP 503.
* Translations: the user interface is translated into every language of ownCloud 11.1. The Polish
  translation was reviewed by the maintainer; the others were made with AI assistance (translation,
  review with a back-translation, adversarial review; CHANGELOG.md, 1.0.3) and have not been
  reviewed by native speakers yet. If a text reads wrong in your language, please open an issue or
  correct it ([CONTRIBUTING.md](https://github.com/takenek/impersonate/blob/main/CONTRIBUTING.md)).
  The reviewers rated their confidence lower where ownCloud itself has few or no translations. A
  native speaker's review is needed most for Acholi (`ach`), Adyghe (`ady`), Akan (`ak`), Amharic
  (`am_ET`), Burmese (`my_MM`), Central Atlas Tamazight (`tzm`), Low German (`nds`), Malagasy (`mg`),
  Maltese (`mt_MT`), N'Ko (`nqo`), Sundanese (`su`) and Tajik (`tg_TJ`): there an additional,
  independent check of the meaning of every text was made. In these and some other languages
  ownCloud itself is hardly translated, so the app may be more complete there than ownCloud.
* In Central Atlas Tamazight (`tzm`) ownCloud 11.1.0's own translations carry a plural rule with an
  unclosed parenthesis: the browser reports a script error from ownCloud's `core/js/l10n.js` on every
  page in that language. The translation of the app uses the corrected rule and adds no error.

## 7. Security review

The code was reviewed with Anthropic's Mythos 5.2 on 2026-11-27 (full source review of the plugin,
advisory check of its dependencies, remediation of every accepted finding that can be fixed within
the plugin in release 1.0.1, a verification of these fixes that led to release 1.0.2; see
[CHANGELOG.md](CHANGELOG.md) and [SECURITY.md](SECURITY.md)). Release 1.0.3 adds translations,
updates the QA tools and fixes how a refusal is shown behind nginx; it does not change what the
review covered (an independent review of its changes was part of the release). Release 1.0.4 is
the result of a further full review of 1.0.3 on 2026-11-28 (no vulnerability of critical, high or
medium risk; twelve of low risk and nineteen observations, mostly in failure paths, maintenance
procedures and the release tooling): every finding that can be fixed within the plugin is fixed
and tested on ownCloud 11.1.0 (SQLite, MariaDB with Apache, PostgreSQL with nginx). The
reviews covered the code of this plugin only: ownCloud itself, other apps and the configuration of
your instance were not part of them. An automated review is not a certification: report anything
they missed as described in SECURITY.md.

## 8. License

GNU Affero General Public License version 3 ([LICENSE](LICENSE)); additional attribution terms for
the material of this fork according to AGPLv3 section 7(b)/(c): [COPYRIGHT](COPYRIGHT).
