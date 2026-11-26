#!/usr/bin/env node
/**
 * Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
 * Original author: Marek Królikowski (TaKeN)
 * Original project: https://github.com/takenek/impersonate
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE and COPYRIGHT for the license and the AGPL section 7 attribution terms.
 *
 * Headless browser test of the impersonate UI (Playwright): user list column and icons, impersonating
 * by clicking, banner, switching back by logging out, admin settings panel, group admin view.
 * Expects the users of tests/e2e/setup-users.sh.
 *
 *   BASE=http://localhost:8080 OC_DIR=... ADMIN_PASSWORD=... USER_PASSWORD=... node tests/ui/ui-impersonate.js
 *
 * Optional: PHP_AS (run occ as the web server user, e.g. "sudo -u www-data"), CHROME (browser binary),
 * SHOTS (screenshot directory, default ./tests/output/screenshots).
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

let pass = 0, fail = 0;
const ok = (m) => { pass++; console.log('  PASS: ' + m); };
const bad = (m) => { fail++; console.log('  FAIL: ' + m); };
const check = (cond, m) => (cond ? ok(m) : bad(m));

async function newSession(browser, label) {
  const context = await browser.newContext({ viewport: { width: 1400, height: 900 } });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(`[${label}] pageerror: ${e.message}`));
  // "Permissions policy violation: unload" comes from ownCloud core (core/js/js.js registers an unload handler), not from the app
  page.on('console', (msg) => { if (msg.type() === 'error' && !/Permissions policy violation: unload/.test(msg.text())) errors.push(`[${label}] console.error: ${msg.text()}`); });
  page.on('response', (r) => { if (r.status() >= 500 || (r.url().includes('/apps/impersonate/') && r.status() >= 400 && !r.url().endsWith('/user'))) errors.push(`[${label}] HTTP ${r.status()} ${r.url()}`); });
  return { context, page, errors };
}

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
  try {
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

    console.log('== admin impersonates alice via icon');
    await Promise.all([
      a.page.waitForURL((u) => !u.pathname.includes('/settings/users'), { timeout: 15000 }),
      a.page.click('#userlist tr[data-test-uid="alice"] a.impersonate'),
    ]);
    await a.page.waitForLoadState('networkidle');
    check(await currentUser(a.page) === 'alice', 'now logged in as alice');
    const banner = a.page.locator('#impersonate-notification');
    check(await banner.count() === 1, 'impersonation banner present');
    if (await banner.count()) {
      const txt = (await banner.innerText()).trim();
      check(/alice/.test(txt), `banner text mentions alice ("${txt}")`);
      check(await banner.isVisible(), 'banner visible');
    }
    await a.page.screenshot({ path: path.join(SHOTS, '02-impersonating-alice.png') });
    await closeOverlays(a.page);
    const pe = await a.page.$eval('#impersonate-notification a', (el) => getComputedStyle(el).pointerEvents);
    check(pe !== 'none', `banner link is clickable (pointer-events: ${pe})`);

    console.log('== logout returns to admin');
    await logoutViaMenu(a.page);
    check(await currentUser(a.page) === 'admin', 'after logout back to admin');
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
        await a.page.click('label[for=impersonateIncludeGroups]');
        await a.page.waitForTimeout(800);
        check(await a.page.locator('#selectIncludedGroups').isVisible(), 'group selector shown for "specific groups"');
        const s2 = await a.page.locator('#selectIncludedGroups .select2-container').count();
        check(s2 === 1, 'select2 group picker initialised');
        await a.page.screenshot({ path: path.join(SHOTS, '05-admin-settings-groups.png'), fullPage: true });
        await a.page.click('label[for=impersonateNoGroupAdmins]');
        await a.page.waitForTimeout(800);
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
  }
  console.log('== browser errors: ' + allErrors.length);
  allErrors.forEach((e) => console.log('  ' + e));
  console.log(`== result: ${pass} passed, ${fail} failed`);
  process.exit(fail || allErrors.length ? 1 : 0);
})();
