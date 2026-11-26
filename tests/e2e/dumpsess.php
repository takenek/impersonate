<?php
/**
 * Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
 * Original author: Marek Królikowski (TaKeN)
 * Original project: https://github.com/takenek/impersonate
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE and COPYRIGHT for the license and the AGPL section 7 attribution terms.
 *
 * Test helper: print the keys of an ownCloud session (CryptoSessionData), passwords masked.
 *
 *   OC_DIR=... SESSION_DIR=... [KNOWN_PW="name=pw;..."] php dumpsess.php <session-id> <passphrase>
 *
 * Must run as the user that owns the session files (the web server user).
 */
if (\PHP_SAPI !== 'cli' || $argc < 3) {
	exit(1);
}
[$sid, $passphrase] = [$argv[1], $argv[2]];
$ocDir = \getenv('OC_DIR') ?: '/var/www/owncloud';
$sessionDir = \getenv('SESSION_DIR') ?: \sys_get_temp_dir();
if (!\preg_match('/^[A-Za-z0-9,-]+$/', $sid)) {
	echo "invalid session id\n";
	exit(1);
}
require_once $ocDir . '/lib/base.php';
$raw = @\file_get_contents("$sessionDir/sess_$sid");
if ($raw === false) {
	echo "NO SESSION FILE\n";
	exit(1);
}
$known = [];
foreach (\explode(';', \getenv('KNOWN_PW') ?: '') as $kv) {
	if (\strpos($kv, '=') !== false) {
		[$name, $pw] = \explode('=', $kv, 2);
		$known[$pw] = $name;
	}
}
$mask = static function ($pw) use ($known) {
	return '<password len=' . \strlen((string)$pw) . ' = ' . ($known[$pw] ?? 'unknown') . "'s password>";
};
$outer = [];
$offset = 0;
while ($offset < \strlen($raw)) {
	$bar = \strpos($raw, '|', $offset);
	if ($bar === false) {
		break;
	}
	$key = \substr($raw, $offset, $bar - $offset);
	$value = @\unserialize(\substr($raw, $bar + 1));
	$outer[$key] = $value;
	$offset = $bar + 1 + \strlen(\serialize($value));
}
$crypto = \OC::$server->getCrypto();
echo 'outer keys: ' . \implode(',', \array_keys($outer)) . "\n";
$inner = \json_decode($crypto->decrypt($outer['encrypted_session_data'] ?? '', $passphrase), true) ?? [];
foreach ($inner as $k => $v) {
	if ($k === 'password::sessioncredentials/credentials') {
		$c = \json_decode($crypto->decrypt($v), true);
		if (isset($c['password'])) {
			$c['password'] = $mask($c['password']);
		}
		echo "  $k => " . \json_encode($c) . "\n";
		continue;
	}
	if (\in_array($k, ['requesttoken', 'privateKey', 'impersonatorPrivateKey', 'impersonatorParkedToken'], true)) {
		echo "  $k => <" . \strlen((string)\json_encode($v)) . " bytes>\n";
		continue;
	}
	echo "  $k => " . \json_encode($v) . "\n";
}
