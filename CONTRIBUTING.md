# Contributing

Thank you for your interest in Impersonate for ownCloud 11.

* **Security problems:** do not open an issue – report them privately as described in
  [SECURITY.md](SECURITY.md).
* **Bugs and feature requests:** open an issue at <https://github.com/takenek/impersonate/issues> with
  the app version, the ownCloud and PHP versions, steps to reproduce and what you expected.
* **Pull requests:** keep them focused, add or adjust tests (`tests/unit`, `tests/e2e`,
  `tests/acceptance`) and make sure CI passes (see README section 5 for running the tests locally).
  Code style: `make test-php-style-fix`; static analysis: `make test-php-phpstan test-php-phan`.
  The tools are installed from lockfiles (`vendor-bin/*/composer.lock`, `tests/ui/package-lock.json`):
  commit the lockfile together with a change of its manifest.
* **Translations:** the app has a translation for every language of ownCloud 11.1 in `l10n/`
  (`<locale>.json` and `<locale>.js` hold the same texts). Except Polish they were made with AI
  assistance and are not yet reviewed by native speakers, so corrections are very welcome: change
  the text in both files, keep the placeholders (`{user}`, `{currentUser}`, `%s`) and the names of
  settings and paths (`max_duration_minutes`, `forbidden_prefixes`, `'allow_subadmins' => false`, …)
  exactly, and say in the pull request which language you speak natively. A translation may be the
  English text itself only where ownCloud translates that text the same way (e.g. "Error" in
  Spanish). `tests/unit/L10nTest.php` checks completeness, placeholders and that both files agree. A
  new text in the code needs its translation in every language in the same change.

By contributing you agree that your contribution is licensed under the GNU Affero General Public
License version 3 or later (see [LICENSE](LICENSE) and [COPYRIGHT](COPYRIGHT)), and you may add an
accurate copyright notice for your contribution without removing existing notices.
