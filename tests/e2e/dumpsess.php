<?php
/**
 * Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
 * Original author: Marek Królikowski (TaKeN)
 * Original project: https://github.com/takenek/impersonate
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE and COPYRIGHT for the license and the AGPL section 7 attribution terms.
 *
 * Test helper: print the keys of an ownCloud session (CryptoSessionData). Values are only
 * printed for the keys listed in $printable (identifiers and flags the tests compare); every
 * other value is redacted, passwords are replaced by the name of their owner.
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
// nothing about the password itself, not even its length
$mask = static function ($pw) use ($known) {
	return '<' . (isset($known[$pw]) ? $known[$pw] . "'s password" : 'a password that is not one of the known ones') . '>';
};
// identifiers and flags only
$printable = [
	'user_id',
	'loginname',
	'encryptionInitialized',
	'impersonator',
	'impersonationTarget',
	'impersonationStart',
	'impersonationTokenWatermark',
	'impersonationSigningKeyExisted',
	'impersonatorEncryptionInitialized',
];
$outer = [];
$offset = 0;
while ($offset < \strlen($raw)) {
	$bar = \strpos($raw, '|', $offset);
	if ($bar === false) {
		break;
	}
	$key = \substr($raw, $offset, $bar - $offset);
	// the session file is data: no object of it is instantiated
	$value = @\unserialize(\substr($raw, $bar + 1), ['allowed_classes' => false]);
	$outer[$key] = $value;
	$offset = $bar + 1 + \strlen(\serialize($value));
}
$crypto = \OC::$server->getCrypto();
echo 'outer keys: ' . \implode(',', \array_keys($outer)) . "\n";
$encrypted = $outer['encrypted_session_data'] ?? '';
$inner = \json_decode($crypto->decrypt(\is_string($encrypted) ? $encrypted : '', $passphrase), true) ?? [];
foreach ($inner as $k => $v) {
	if ($k === 'password::sessioncredentials/credentials') {
		$c = \json_decode($crypto->decrypt($v), true);
		$shown = [];
		if (\is_array($c)) {
			// whose credentials they are, and whose password
			if (isset($c['uid']) && \is_string($c['uid'])) {
				$shown['uid'] = $c['uid'];
			}
			if (isset($c['password'])) {
				$shown['password'] = $mask($c['password']);
			}
		}
		echo "  $k => " . \json_encode($shown) . "\n";
		continue;
	}
	if (\in_array($k, $printable, true) && (\is_scalar($v) || $v === null)) {
		echo "  $k => " . \json_encode($v) . "\n";
		continue;
	}
	echo "  $k => <redacted>\n";
}
