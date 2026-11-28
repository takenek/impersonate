#!/usr/bin/env node
/**
 * Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
 * Original author: Marek Królikowski (TaKeN)
 * Original project: https://github.com/takenek/impersonate
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE and COPYRIGHT for the license and the AGPL section 7 attribution terms.
 *
 * Headless browser test of the impersonate UI (Playwright): user list column and icons, the
 * confirmation before an impersonation starts, a refused impersonation (also with an error page of
 * the web server instead of the app's answer), the confirmation and the admin section in several
 * languages, which account the request names, banner (in the language of the impersonated account),
 * switching back by logging out, admin settings panel (the policy is stored by one request), group
 * admin view. Expects the users of tests/e2e/setup-users.sh.
 *
 *   BASE=http://localhost:8080 OC_DIR=... ADMIN_PASSWORD=... USER_PASSWORD=... node tests/ui/ui-impersonate.js
 *
 * playwright-core is installed from tests/ui/package-lock.json: npm ci --prefix tests/ui
 *
 * Optional: PHP_AS (run occ as the web server user, e.g. "sudo -u www-data"), CHROME (browser binary),
 * SHOTS (screenshot directory, default ./tests/output/screenshots), UI_LANGS (comma-separated locale
 * codes of the language checks; default pl,de_DE,fr,es_419,pt_BR,ru,ar,he,ja,zh-Hans,zh_TW,sr@latin).
 */
const { chromium } = require('playwright-core');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const BASE = process.env.BASE || 'http://localhost:8080';
const CHROME = process.env.CHROME || '';
const SHOTS = process.env.SHOTS || path.join(__dirname, '..', 'output', 'screenshots');
const OC_DIR = process.env.OC_DIR;
const PHP_AS = process.env.PHP_AS || '';
const ADMIN_PW = process.env.ADMIN_PASSWORD;
const USER_PW = process.env.USER_PASSWORD;
if (!OC_DIR || !ADMIN_PW || !USER_PW) {
  console.error('set OC_DIR, ADMIN_PASSWORD and USER_PASSWORD');
  process.exit(2);
}
fs.mkdirSync(SHOTS, { recursive: true });
const occ = (args) => execSync(`${PHP_AS} php ${OC_DIR}/occ ${args}`, { stdio: 'pipe' }).toString();
// the translations of the app (l10n/<locale>.json): the texts the language checks expect
const translations = (lang) => JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'l10n', `${lang}.json`), 'utf8')).translations;
const norm = (s) => s.replace(/\s+/g, ' ').trim();

let pass = 0, fail = 0;
const ok = (m) => { pass++; console.log('  PASS: ' + m); };
const bad = (m) => { fail++; console.log('  FAIL: ' + m); };
const check = (cond, m) => (cond ? ok(m) : bad(m));

// locale: the language the browser asks for (it must not depend on the machine of the test)
async function newSession(browser, label, locale = 'en-US') {
  const context = await browser.newContext({ viewport: { width: 1400, height: 900 }, locale });
  const page = await context.newPage();
  const errors = [];
  // requests to the app: [method, path below /apps/impersonate/, body]
  const requests = [];
  // set while the test makes a request fail on purpose
  const expected = { failures: false };
  page.on('pageerror', (e) => errors.push(`[${label}] pageerror: ${e.message}`));
  // "Permissions policy violation: unload" comes from ownCloud core (core/js/js.js registers an unload handler), not from the app
  page.on('console', (msg) => { if (msg.type() === 'error' && !expected.failures && !/Permissions policy violation: unload/.test(msg.text())) errors.push(`[${label}] console.error: ${msg.text()}`); });
  page.on('response', (r) => { if (r.status() >= 500 || (r.url().includes('/apps/impersonate/') && r.status() >= 400 && !r.url().endsWith('/user'))) errors.push(`[${label}] HTTP ${r.status()} ${r.url()}`); });
  page.on('request', (r) => { const m = /\/apps\/impersonate\/([a-z]+)$/.exec(new URL(r.url()).pathname); if (m && r.method() !== 'GET') requests.push([r.method(), m[1], r.postData() || '']); });
  return { context, page, errors, requests, expected };
}

const DIALOG = '.oc-dialog';
// answer the confirmation dialog of the impersonate icon (shot: a screenshot of the dialog before it is answered)
async function answerDialog(page, yes, shot) {
  await page.waitForSelector(DIALOG, { state: 'visible', timeout: 5000 });
  const text = (await page.locator(`${DIALOG} .oc-dialog-content`).last().innerText()).trim();
  if (shot) {
    await page.screenshot({ path: shot });
  }
  await page.locator(`${DIALOG} .oc-dialog-buttonrow button${yes ? '.primary' : ':not(.primary)'}`).last().click();
  return text;
}

const appConfig = (key) => occ(`config:app:get impersonate ${key}`).trim();
// The language of a user's pages is the stored setting; without one ownCloud stores what the browser
// asks for at the next login. The checks look at texts, so the language is set, and put back at the end.
const getLang = (uid) => { try { return occ(`user:setting ${uid} core lang`).trim(); } catch (e) { return null; } };
const setLang = (uid, lang) => occ(lang === null ? `user:setting ${uid} core lang --delete` : `user:setting ${uid} core lang --value=${lang}`);

async function login(page, user, pw) {
  await page.goto(`${BASE}/index.php/login`);
  await page.fill('#user', user);
  await page.fill('#password', pw);
  await Promise.all([page.waitForLoadState('networkidle'), page.click('#submit')]);
}

async function currentUser(page) {
  return page.evaluate(() => (window.OC && OC.getCurrentUser ? OC.getCurrentUser().uid : null));
}

async function closeOverlays(page) {
  // first-run wizard (colorbox) may cover the page on a user's first visit
  if (await page.locator('#cboxOverlay').isVisible().catch(() => false)) {
    await page.evaluate(() => { if (window.$ && $.colorbox) { $.colorbox.close(); } });
    await page.waitForSelector('#cboxOverlay', { state: 'hidden', timeout: 5000 }).catch(() => {});
  }
}

async function logoutViaMenu(page) {
  await closeOverlays(page);
  await page.click('#expand');
  // logout -> 303 /login -> 303 default app: wait for the new document, then for it to settle
  await Promise.all([page.waitForEvent('load'), page.click('#logout')]);
  await page.waitForLoadState('networkidle');
}

async function usersPage(page) {
  await page.goto(`${BASE}/index.php/settings/users`);
  await page.waitForFunction(() => window.$ && $('#userlist tbody tr').filter(function () { return !!$(this).data('uid'); }).length > 0, null, { timeout: 15000 });
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(500);
  // UserList stores the uid via jQuery.data(), expose it as an attribute for selectors
  await page.evaluate(() => $('#userlist tbody tr').each(function () { const uid = $(this).data('uid'); if (uid) this.setAttribute('data-test-uid', uid); }));
}

(async () => {
  const browser = await chromium.launch(CHROME ? { executablePath: CHROME, headless: true } : { headless: true });
  const allErrors = [];
  const adminLang = getLang('admin');
  const aliceLang = getLang('alice');
  try {
    setLang('admin', 'en');
    console.log('== admin: users page');
    const a = await newSession(browser, 'admin');
    await login(a.page, 'admin', ADMIN_PW);
    check(await currentUser(a.page) === 'admin', 'admin logged in via login form');
    await usersPage(a.page);
    await a.page.screenshot({ path: path.join(SHOTS, '01-admin-users.png'), fullPage: true });
    check(await a.page.locator('#userlist th#impersonateId').count() === 1, 'Impersonate column header present');
    const rows = await a.page.$$eval('#userlist tbody tr[data-test-uid]', (trs) => trs.map((tr) => ({
      uid: tr.dataset.testUid,
      name: (tr.querySelector('.name') || {}).textContent,
      icon: !!tr.querySelector('a.impersonate'),
      disabled: !!tr.querySelector('td.impersonateDisabled'),
      cells: tr.querySelectorAll(':scope > td, :scope > th').length,
    })));
    console.log('  rows: ' + JSON.stringify(rows));
    const headerCells = await a.page.$$eval('#userlist thead th', (ths) => ths.length);
    check(rows.length >= 5, `user rows rendered (${rows.length})`);
    check(rows.filter((r) => r.uid !== 'admin').every((r) => r.icon), 'impersonate icon on every other user');
    check(rows.filter((r) => r.uid === 'admin').every((r) => r.disabled && !r.icon), 'no icon on own row');
    check(rows.every((r) => r.cells === headerCells), `row cell count matches header (${headerCells})`);

    // a user who never logged in can not be impersonated -> no icon
    try { execSync(`${PHP_AS} env OC_PASS=Never-Logged-In-1 php ${OC_DIR}/occ user:add --password-from-env neverloggedin`, { stdio: 'pipe' }); } catch (e) { /* exists */ }
    await usersPage(a.page);
    const never = await a.page.$$eval('#userlist tbody tr[data-test-uid="neverloggedin"]', (trs) => trs.map((tr) => !!tr.querySelector('a.impersonate')));
    check(never.length === 1 && never[0] === false, 'no icon for a user who never logged in');
    occ('user:delete neverloggedin');
    await usersPage(a.page);

    console.log('== the icon asks before it switches');
    await a.page.click('#userlist tr[data-test-uid="alice"] a.impersonate');
    const question = await answerDialog(a.page, false, path.join(SHOTS, '01b-confirmation.png'));
    check(/"alice"/.test(question), `the confirmation names the account ("${question}")`);
    await a.page.waitForTimeout(500);
    check(a.requests.length === 0, 'answering "No" sends no request');
    check(await currentUser(a.page) === 'admin', 'answering "No" changes nothing');

    console.log('== a refused impersonation says so and keeps the session');
    // The account is disabled after the page was loaded, so the server refuses (HTTP 404 with the
    // reason as JSON). A web server that replaces error pages (nginx as the ownCloud documentation
    // configures it) keeps only the status: then the general text is shown. Either way the answer is
    // a refusal, not "the result of the request is unknown" with a reload of the page.
    await usersPage(a.page);
    occ('user:disable bob');
    // the browser reports the 404 of the refusal on its console
    a.expected.failures = true;
    try {
      await a.page.click('#userlist tr[data-test-uid="bob"] a.impersonate');
      await answerDialog(a.page, true);
      const alertHandle = await a.page.waitForFunction(() => {
        // the dialogs are position: fixed (no offsetParent); a closed one is display: none
        const shown = [...document.querySelectorAll('.oc-dialog')].filter((d) => d.getClientRects().length > 0);
        const last = shown[shown.length - 1];
        const content = last && last.querySelector('.oc-dialog-content');
        return content && !/Do you want/.test(content.innerText) ? content.innerText : false;
      }, null, { timeout: 10000 });
      const refusal = norm(await alertHandle.jsonValue());
      check(['Can not impersonate a disabled user', 'Can not impersonate'].includes(refusal), `the refusal is shown ("${refusal}")`);
      await a.page.locator(`${DIALOG} .oc-dialog-buttonrow button`).last().click();
      await a.page.waitForTimeout(500);
      check(a.requests.length === 1 && a.requests[0][2] === 'target=bob', `one request, for bob (${JSON.stringify(a.requests)})`);
      check(await currentUser(a.page) === 'admin' && new URL(a.page.url()).pathname.includes('/settings/users'), 'the session and the page stay the same');
    } finally {
      occ('user:enable bob');
      a.requests.length = 0;
    }
    // the same as nginx answers it: HTTP 404 with an HTML error page instead of the app's JSON
    await usersPage(a.page);
    await a.page.route('**/apps/impersonate/user', (route) => route.fulfill({ status: 404, contentType: 'text/html', body: '<!DOCTYPE html><html><body>Not found</body></html>' }));
    try {
      await a.page.click('#userlist tr[data-test-uid="carol"] a.impersonate');
      await answerDialog(a.page, true);
      const pageHandle = await a.page.waitForFunction(() => {
        const shown = [...document.querySelectorAll('.oc-dialog')].filter((d) => d.getClientRects().length > 0);
        const last = shown[shown.length - 1];
        const content = last && last.querySelector('.oc-dialog-content');
        return content && !/Do you want/.test(content.innerText) ? content.innerText : false;
      }, null, { timeout: 10000 });
      const general = norm(await pageHandle.jsonValue());
      check(general === 'Can not impersonate', `an error page instead of the reason is shown as a refusal ("${general}")`);
      await a.page.locator(`${DIALOG} .oc-dialog-buttonrow button`).last().click();
      await a.page.waitForTimeout(500);
      check(await currentUser(a.page) === 'admin' && new URL(a.page.url()).pathname.includes('/settings/users'), '... and the session and the page stay the same');
    } finally {
      await a.page.unroute('**/apps/impersonate/user');
      a.expected.failures = false;
      a.requests.length = 0;
    }

    console.log('== the confirmation and the admin section in other languages');
    // Every translation is complete (tests/unit/L10nTest.php): the dialog must show exactly the text
    // of the language (a translated title and buttons around an English question is not a
    // translation), the admin section is translated on the server. The languages cover the kinds of
    // locale codes of ownCloud ("pl", "de_DE", "es_419", "sr@latin", "zh-Hans"), right-to-left
    // scripts and scripts without spaces. UI_LANGS (comma-separated) replaces the list.
    const QUESTION = 'Do you want to log in as user "{user}"? Everything you do until you log out is done as this user.';
    const LANGS = (process.env.UI_LANGS || 'pl,de_DE,fr,es_419,pt_BR,ru,ar,he,ja,zh-Hans,zh_TW,sr@latin').split(',').filter(Boolean);
    for (const lang of LANGS) {
      const tr = translations(lang);
      setLang('admin', lang);
      // the browser asks for English: the stored language of the user must win
      const l = await newSession(browser, `admin-${lang}`, 'en-US');
      await login(l.page, 'admin', ADMIN_PW);
      const htmlLang = await l.page.evaluate(() => document.documentElement.lang);
      // ownCloud writes "sr" into the page for sr@latin (lib/private/TemplateLayout.php)
      check(htmlLang === (lang === 'sr@latin' ? 'sr' : lang), `${lang}: the pages of this session are in that language (${htmlLang})`);
      await usersPage(l.page);
      await l.page.click('#userlist tr[data-test-uid="alice"] a.impersonate');
      await l.page.waitForSelector(DIALOG, { state: 'visible', timeout: 5000 });
      const title = norm(await l.page.locator(`${DIALOG} .oc-dialog-title`).last().innerText());
      const shot = path.join(SHOTS, `01c-confirmation-${lang.replace(/[^A-Za-z0-9_-]/g, '_')}.png`);
      const question = norm(await answerDialog(l.page, false, shot));
      check(question === norm(tr[QUESTION].replace('{user}', 'alice')), `${lang}: the question is the translation and names the account ("${question}")`);
      check(title === norm(tr.Impersonate), `${lang}: the title of the dialog is translated ("${title}")`);
      await l.page.waitForTimeout(500);
      check(l.requests.length === 0 && await currentUser(l.page) === 'admin', `${lang}: answering "no" changes nothing`);
      await l.page.goto(`${BASE}/index.php/settings/admin?sectionid=authentication`);
      await l.page.waitForLoadState('networkidle');
      const heading = norm(await l.page.locator('#impersonateTemplateSettings h2').innerText());
      check(heading === norm(tr['Impersonate Settings']), `${lang}: the admin section is translated ("${heading}")`);
      allErrors.push(...l.errors);
      await l.context.close();
    }
    setLang('admin', 'en');
    await usersPage(a.page);

    console.log('== the account is the one the icon was created for, not the text of the row');
    // an account id that looks like a number, and a row whose visible text names somebody else
    try { execSync(`${PHP_AS} env OC_PASS=${USER_PW} php ${OC_DIR}/occ user:add --password-from-env 20261127`, { stdio: 'pipe' }); } catch (e) { /* exists */ }
    const n = await newSession(browser, '20261127');
    await login(n.page, '20261127', USER_PW);
    check(await currentUser(n.page) === '20261127', 'the user with a number-like id logged in once');
    await n.context.close();
    await usersPage(a.page);
    await a.page.evaluate(() => {
      $('#userlist tbody tr').each(function () {
        if ($(this).data('uid') === '20261127') { $(this).find('.name').text('bob'); }
      });
    });
    await a.page.click('#userlist tr[data-test-uid="20261127"] a.impersonate');
    const numeric = await answerDialog(a.page, true);
    check(/"20261127"/.test(numeric), `the confirmation names the account id, not the text of the row ("${numeric}")`);
    await a.page.waitForURL((u) => !u.pathname.includes('/settings/users'), { timeout: 15000 });
    await a.page.waitForLoadState('networkidle');
    check(a.requests.length === 1 && a.requests[0][2] === 'target=20261127', `the request names that account (${JSON.stringify(a.requests)})`);
    check(await currentUser(a.page) === '20261127', 'now logged in as that account');
    await logoutViaMenu(a.page);
    check(await currentUser(a.page) === 'admin', 'after logout back to admin');
    occ('user:delete 20261127');
    a.requests.length = 0;
    await usersPage(a.page);

    console.log('== admin impersonates alice via icon');
    // the pages of the impersonation are in the language of the account: a right-to-left one here
    setLang('alice', 'ar');
    await a.page.click('#userlist tr[data-test-uid="alice"] a.impersonate');
    await Promise.all([
      a.page.waitForURL((u) => !u.pathname.includes('/settings/users'), { timeout: 15000 }),
      answerDialog(a.page, true),
    ]);
    await a.page.waitForLoadState('networkidle');
    check(a.requests.length === 1 && a.requests[0][0] === 'POST' && a.requests[0][1] === 'user' && a.requests[0][2] === 'target=alice', 'one request, for alice');
    check(await currentUser(a.page) === 'alice', 'now logged in as alice');
    const banner = a.page.locator('#impersonate-notification');
    check(await banner.count() === 1, 'impersonation banner present');
    if (await banner.count()) {
      const txt = norm(await banner.innerText());
      const expected = norm(translations('ar')['Logged in as {currentUser}'].replace('{currentUser}', 'alice'));
      check(txt === expected, `banner text is the translation of the account's language and names alice ("${txt}")`);
      check(await banner.isVisible(), 'banner visible');
    }
    await a.page.screenshot({ path: path.join(SHOTS, '02-impersonating-alice.png') });
    await closeOverlays(a.page);
    const pe = await a.page.$eval('#impersonate-notification a', (el) => getComputedStyle(el).pointerEvents);
    check(pe !== 'none', `banner link is clickable (pointer-events: ${pe})`);

    console.log('== logout returns to admin');
    await logoutViaMenu(a.page);
    check(await currentUser(a.page) === 'admin', 'after logout back to admin');
    setLang('alice', aliceLang);
    await a.page.screenshot({ path: path.join(SHOTS, '03-back-to-admin.png') });

    console.log('== admin settings panel');
    await a.page.goto(`${BASE}/index.php/settings/admin?sectionid=authentication`);
    await a.page.waitForLoadState('networkidle');
    const section = a.page.locator('#impersonateTemplateSettings');
    check(await section.count() === 1, 'Impersonate settings section rendered');
    await a.page.screenshot({ path: path.join(SHOTS, '04-admin-settings.png'), fullPage: true });
    if (await section.count()) {
      const visible = await a.page.locator('label[for=impersonateAllGroupAdmins]').isVisible();
      check(visible, 'group-admin radio buttons visible');
      if (visible) {
        // every change of the panel is one request that carries the whole policy
        const saved = async (action) => {
          a.requests.length = 0;
          const [response] = await Promise.all([
            a.page.waitForResponse((r) => r.url().endsWith('/apps/impersonate/policy') && r.request().method() === 'PUT', { timeout: 10000 }),
            action(),
          ]);
          await a.page.waitForTimeout(300);
          return { status: response.status(), sent: a.requests.map((r) => JSON.parse(r[2])), stored: (await response.json()).policy };
        };
        let r = await saved(() => a.page.click('label[for=impersonateIncludeGroups]'));
        check(r.status === 200 && r.sent.length === 1, `"specific groups" is stored by one request (${r.sent.length})`);
        check(JSON.stringify(r.sent[0]) === '{"mode":"include_groups","groups":[],"allowGroupAdminTargets":false}', `... that carries the whole policy (${JSON.stringify(r.sent[0])})`);
        check(appConfig('impersonate_include_groups') === 'true' && appConfig('impersonate_all_groupadmins') === 'false' && appConfig('impersonate_include_groups_list') === '[]', '... and the server stored it');
        check(await a.page.locator('#selectIncludedGroups').isVisible(), 'group selector shown for "specific groups"');
        const s2 = await a.page.locator('#selectIncludedGroups .select2-container').count();
        check(s2 === 1, 'select2 group picker initialised');
        // pick the group g1 in the group picker
        await a.page.click('#selectIncludedGroups .select2-container');
        await a.page.waitForSelector('.select2-results li', { timeout: 10000 });
        r = await saved(() => a.page.locator('.select2-results li', { hasText: /^g1/ }).first().click());
        check(JSON.stringify(r.sent[0].groups) === '["g1"]' && JSON.stringify(r.stored.groups) === '["g1"]', `a picked group is stored (${JSON.stringify(r.sent)})`);
        check(appConfig('impersonate_include_groups_list') === '["g1"]', '... on the server');
        await a.page.keyboard.press('Escape');
        await a.page.screenshot({ path: path.join(SHOTS, '05-admin-settings-groups.png'), fullPage: true });
        r = await saved(() => a.page.click('label[for=impersonateGroupAdminTargets]'));
        check(r.sent.length === 1 && r.sent[0].allowGroupAdminTargets === true && r.sent[0].mode === 'include_groups' && JSON.stringify(r.sent[0].groups) === '["g1"]', 'the group admin target option is stored together with the rest');
        // stored with the delegation it was given for (two saves that overlap can not mix them)
        const consent = (() => { try { return JSON.parse(appConfig('impersonate_allow_groupadmin_targets')); } catch (e) { return null; } })();
        check(consent !== null && consent.mode === 'include_groups' && JSON.stringify(consent.groups) === '["g1"]',
          `... on the server, with the delegation it was given for (${JSON.stringify(consent)})`);

        // a request that fails: the panel must not go on showing what was not stored
        a.expected.failures = true;
        await a.page.route('**/apps/impersonate/policy', (route) => route.abort());
        await a.page.click('label[for=impersonateAllGroupAdmins]');
        await a.page.waitForEvent('load', { timeout: 15000 });
        await a.page.waitForLoadState('networkidle');
        await a.page.unroute('**/apps/impersonate/policy');
        a.expected.failures = false;
        check(await a.page.isChecked('#impersonateIncludeGroups') && !(await a.page.isChecked('#impersonateAllGroupAdmins')), 'after a failed save the panel shows the policy that is in effect');
        check(appConfig('impersonate_all_groupadmins') === 'false' && appConfig('impersonate_include_groups') === 'true', '... which the failed save did not change');
        check(await a.page.getAttribute('#includedGroups', 'data-groups') === '["g1"]', 'the group list comes back as JSON');

        r = await saved(() => a.page.click('label[for=impersonateNoGroupAdmins]'));
        check(JSON.stringify(r.sent[0]) === '{"mode":"admins","groups":[],"allowGroupAdminTargets":true}', '"only administrators" is stored by one request');
        r = await saved(() => a.page.click('label[for=impersonateGroupAdminTargets]'));
        check(appConfig('impersonate_include_groups') === 'false' && appConfig('impersonate_all_groupadmins') === 'false'
          && appConfig('impersonate_include_groups_list') === '[]' && appConfig('impersonate_allow_groupadmin_targets') === 'false', 'the policy is back to "only administrators"');
      }
    }
    allErrors.push(...a.errors);
    await a.context.close();

    console.log('== group admin carol (allow_subadmins must be true, mode all-groupadmins)');
    occ('config:app:set impersonate impersonate_all_groupadmins --value=true');
    const c = await newSession(browser, 'carol');
    await login(c.page, 'carol', USER_PW);
    await usersPage(c.page);
    await c.page.screenshot({ path: path.join(SHOTS, '06-carol-users.png'), fullPage: true });
    const crows = await c.page.$$eval('#userlist tbody tr[data-test-uid]', (trs) => trs.map((tr) => ({ uid: tr.dataset.testUid, icon: !!tr.querySelector('a.impersonate') })));
    console.log('  carol sees: ' + JSON.stringify(crows));
    check(crows.some((r) => r.uid === 'alice' && r.icon), 'carol has icon for alice');
    occ('config:app:set impersonate impersonate_all_groupadmins --value=false');
    await usersPage(c.page);
    const crows2 = await c.page.$$eval('#userlist tbody tr[data-test-uid]', (trs) => trs.map((tr) => ({ uid: tr.dataset.testUid, icon: !!tr.querySelector('a.impersonate') })));
    check(crows2.length > 0 && crows2.every((r) => !r.icon), '"only admins" mode: group admin sees no impersonate icons');
    allErrors.push(...c.errors);
    await c.context.close();
  } catch (e) {
    bad('exception: ' + (e.stack || e));
  } finally {
    await browser.close();
    // whatever happened above: leave the instance as the other tests expect it
    for (const args of ['user:delete neverloggedin', 'user:delete 20261127',
      'config:app:set impersonate impersonate_all_groupadmins --value=false',
      'config:app:set impersonate impersonate_include_groups --value=false',
      'config:app:set impersonate impersonate_include_groups_list --value=[]',
      'config:app:set impersonate impersonate_allow_groupadmin_targets --value=false',
      'impersonate:active --end']) {
      try { occ(args); } catch (e) { /* nothing to clean up */ }
    }
    try { setLang('admin', adminLang); } catch (e) { /* it had none and has none */ }
    try { setLang('alice', aliceLang); } catch (e) { /* it had none and has none */ }
  }
  console.log('== browser errors: ' + allErrors.length);
  allErrors.forEach((e) => console.log('  ' + e));
  console.log(`== result: ${pass} passed, ${fail} failed`);
  process.exit(fail || allErrors.length ? 1 : 0);
})();
