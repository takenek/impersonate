<?php
/**
 * Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
 * Original author: Marek Królikowski (TaKeN)
 * Original project: https://github.com/takenek/impersonate
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE and COPYRIGHT for the license and the AGPL section 7 attribution terms.
 *
 * @author    Marek Królikowski (TaKeN)
 * @link      https://github.com/takenek
 * @license   AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of the
 * GNU Affero General Public License as published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version.
 */

namespace OCA\Impersonate\Tests\Unit\Lib;

require_once __DIR__ . '/../Support/ArraySession.php';

use OC\Authentication\Exceptions\InvalidTokenException;
use OC\Authentication\Exceptions\PasswordlessTokenException;
use OC\Authentication\Token\DefaultToken;
use OC\Authentication\Token\DefaultTokenProvider;
use OC\Authentication\Token\IToken;
use OC\Security\CSRF\CsrfTokenManager;
use OC\User\Session;
use OCA\Impersonate\Tests\Unit\Support\ArraySession;
use OCA\Impersonate\Util;
use OCP\IConfig;
use OCP\ILogger;
use OCP\IRequest;
use OCP\IUser;
use OCP\IUserManager;
use OCP\Security\ISecureRandom;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

class UtilTest extends TestCase {
	/** @var ArraySession */
	private $session;
	/** @var Session|MockObject */
	private $userSession;
	/** @var IRequest|MockObject */
	private $request;
	/** @var DefaultTokenProvider|MockObject */
	private $tokenProvider;
	/** @var IUserManager|MockObject */
	private $userManager;
	/** @var ISecureRandom|MockObject */
	private $secureRandom;
	/** @var CsrfTokenManager|MockObject */
	private $csrfTokenManager;
	/** @var ILogger|MockObject */
	private $logger;
	/** @var IConfig|MockObject */
	private $config;
	/** @var array<string, string> user values "uid/app/key" */
	private $userValues = [];
	/** @var Util */
	private $util;
	/** @var IUser|null user the (mocked) user session currently holds */
	private $sessionUser;
	/** @var array<string, DefaultToken> */
	private $tokens = [];
	/** @var array<string, string|null> token string => password */
	private $passwords = [];
	/** @var array generateToken() calls */
	private $generated = [];
	/** @var string[] */
	private $invalidated = [];
	/** @var int auto increment for token ids */
	private $nextId = 100;

	protected function setUp(): void {
		parent::setUp();
		$this->session = new ArraySession('session-1');
		$this->userSession = $this->createMock(Session::class);
		$this->userSession->method('getUser')->willReturnCallback(function () {
			return $this->sessionUser;
		});
		$this->userSession->method('setUser')->willReturnCallback(function ($user) {
			$this->sessionUser = $user;
		});
		$this->userSession->method('setLoginName')->willReturnCallback(function ($loginName) {
			if ($loginName === null) {
				$this->session->remove('loginname');
			} else {
				$this->session->set('loginname', $loginName);
			}
		});
		$this->userSession->method('getLoginName')->willReturnCallback(function () {
			return $this->session->get('loginname');
		});
		$this->request = $this->createMock(IRequest::class);
		$this->tokenProvider = $this->createMock(DefaultTokenProvider::class);
		$this->tokenProvider->method('getToken')->willReturnCallback(function ($tokenId) {
			if (!isset($this->tokens[$tokenId])) {
				throw new InvalidTokenException();
			}
			return $this->tokens[$tokenId];
		});
		$this->tokenProvider->method('getPassword')->willReturnCallback(function ($token, $tokenId) {
			$password = $this->passwords[$tokenId] ?? null;
			if ($password === null) {
				throw new PasswordlessTokenException();
			}
			return $password;
		});
		$this->tokenProvider->method('generateToken')->willReturnCallback(
			function ($token, $uid, $loginName, $password, $name, $type = IToken::TEMPORARY_TOKEN) {
				$this->generated[] = [$token, $uid, $loginName, $password, $name, $type];
				$this->addToken($token, $uid, $loginName, $password, $name, $type);
				return $this->tokens[$token];
			}
		);
		$this->tokenProvider->method('invalidateToken')->willReturnCallback(function ($token) {
			$this->invalidated[] = $token;
			unset($this->tokens[$token]);
		});
		$this->userManager = $this->createMock(IUserManager::class);
		$this->secureRandom = $this->createMock(ISecureRandom::class);
		$this->secureRandom->method('generate')->willReturn('parked-secret');
		$this->csrfTokenManager = $this->createMock(CsrfTokenManager::class);
		$this->logger = $this->createMock(ILogger::class);
		$this->config = $this->createMock(IConfig::class);
		$this->config->method('getAppValue')->willReturnCallback(function ($app, $key, $default = '') {
			return $default;
		});
		$this->config->method('getUserValue')->willReturnCallback(function ($uid, $app, $key, $default = '') {
			return $this->userValues["$uid/$app/$key"] ?? $default;
		});
		$this->config->method('deleteUserValue')->willReturnCallback(function ($uid, $app, $key) {
			unset($this->userValues["$uid/$app/$key"]);
		});
		$this->util = new Util(
			$this->session,
			$this->userSession,
			$this->request,
			$this->tokenProvider,
			$this->userManager,
			$this->secureRandom,
			$this->csrfTokenManager,
			$this->logger,
			$this->config
		);
	}

	private function addToken(string $token, string $uid, string $loginName, ?string $password, string $name, int $type, int $id = 0): DefaultToken {
		$t = new DefaultToken();
		$t->setId($id ?: $this->nextId++);
		$t->setUid($uid);
		$t->setLoginName($loginName);
		$t->setName($name);
		$t->setType($type);
		$t->setLastCheck(\time());
		if ($password !== null) {
			$t->setPassword('encrypted');
		}
		$this->tokens[$token] = $t;
		$this->passwords[$token] = $password;
		return $t;
	}

	/**
	 * @return IUser|MockObject
	 */
	private function user(string $uid, bool $enabled = true) {
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn($uid);
		$user->method('isEnabled')->willReturn($enabled);
		return $user;
	}

	private function loggedInAdmin(): IUser {
		$admin = $this->user('admin');
		$this->sessionUser = $admin;
		$this->session->data = [
			'user_id' => 'admin',
			'loginname' => 'admin@example.com',
			'password::sessioncredentials/credentials' => 'encrypted-admin-credentials',
			'app_password' => 'admin-app-password',
			'privateKey' => 'admin-private-key',
			'encryptionInitialized' => 2,
			'requesttoken' => 'csrf',
		];
		$this->addToken('session-1', 'admin', 'admin@example.com', 'admin-password', 'Firefox', IToken::TEMPORARY_TOKEN, 10);
		return $admin;
	}

	public function testStartImpersonation(): void {
		$admin = $this->loggedInAdmin();
		$alice = $this->user('alice');
		$this->tokenProvider->method('getTokenByUser')->willReturn([
			$this->addToken('alice-old', 'alice', 'alice', 'pw', 'Phone', IToken::PERMANENT_TOKEN, 41),
		]);
		$this->csrfTokenManager->expects($this->once())->method('refreshToken');

		$this->util->startImpersonation($alice, $admin);

		$this->assertSame($alice, $this->sessionUser);
		$this->assertSame(['session-1'], $this->session->regenerated, 'session id must be rotated');
		$this->assertSame(
			[
				['parked-secret', 'admin', 'admin@example.com', 'admin-password', 'Firefox', IToken::TEMPORARY_TOKEN],
				['session-2', 'alice', 'alice', null, 'Impersonated by admin', IToken::TEMPORARY_TOKEN],
			],
			$this->generated
		);
		$this->assertContains('session-1', $this->invalidated);
		$this->assertTrue($this->util->isImpersonating());
		$this->assertSame('admin', $this->util->getImpersonatorUid());
		$this->assertSame('alice', $this->session->get('loginname'));
		$this->assertNull($this->session->get('password::sessioncredentials/credentials'), 'impersonator credentials must not stay active');
		$this->assertNull($this->session->get('app_password'));
		$this->assertSame('parked-secret', $this->session->get(Util::SESSION_PARKED_TOKEN));
		$this->assertSame(41, $this->session->get(Util::SESSION_TOKEN_WATERMARK));
		$this->assertSame(
			[
				'loginname' => 'admin@example.com',
				'app_password' => 'admin-app-password',
				'password::sessioncredentials/credentials' => 'encrypted-admin-credentials',
			],
			\json_decode($this->session->get(Util::SESSION_IDENTITY_STASH), true)
		);
		// encryption keys are kept active (master key) and copied for the way back
		$this->assertSame('admin-private-key', $this->session->get('privateKey'));
		$this->assertSame('admin-private-key', $this->session->get(Util::SESSION_PRIVATE_KEY));
		$this->assertSame(2, $this->session->get(Util::SESSION_ENCRYPTION_INITIALIZED));
	}

	public function testStartImpersonationWithoutSessionToken(): void {
		$admin = $this->loggedInAdmin();
		unset($this->tokens['session-1']);
		$this->request->method('getHeader')->with('User-Agent')->willReturn('curl');
		$this->tokenProvider->method('getTokenByUser')->willReturn([]);

		$this->util->startImpersonation($this->user('alice'), $admin);

		$this->assertSame(['parked-secret', 'admin', 'admin@example.com', null, 'curl', IToken::TEMPORARY_TOKEN], $this->generated[0]);
		$this->assertTrue($this->util->isImpersonating());
	}

	public function testNestedImpersonationIsRejected(): void {
		$admin = $this->loggedInAdmin();
		$this->session->set(Util::SESSION_IMPERSONATOR, 'someone');
		$this->expectException(\LogicException::class);
		$this->util->startImpersonation($this->user('alice'), $admin);
	}

	private function impersonating(IUser $admin, IUser $alice): void {
		$this->tokenProvider->method('getTokenByUser')->willReturnCallback(function (IUser $user) {
			return \array_values(\array_filter($this->tokens, function (DefaultToken $t) use ($user) {
				return $t->getUID() === $user->getUID();
			}));
		});
		$this->util->startImpersonation($alice, $admin);
		$this->generated = [];
		$this->invalidated = [];
		// the impersonated session writes its own values
		$this->session->set('password::sessioncredentials/credentials', 'alice-credentials');
		$this->session->set('app_password', 'alice-app-password');
	}

	public function testStopImpersonationRestoresTheImpersonator(): void {
		$admin = $this->loggedInAdmin();
		$alice = $this->user('alice');
		$this->impersonating($admin, $alice);
		$this->userManager->method('get')->with('admin')->willReturn($admin);
		$this->csrfTokenManager->expects($this->once())->method('refreshToken');

		$this->assertTrue($this->util->stopImpersonation());

		$this->assertSame($admin, $this->sessionUser);
		$this->assertSame(['session-1', 'session-2'], $this->session->regenerated);
		$this->assertSame(
			[['session-3', 'admin', 'admin@example.com', 'admin-password', 'Firefox', IToken::TEMPORARY_TOKEN]],
			$this->generated,
			'the restored session token must keep the login password'
		);
		$this->assertSame(['session-2', 'parked-secret'], $this->invalidated);
		$this->assertSame('admin@example.com', $this->session->get('loginname'));
		$this->assertSame('encrypted-admin-credentials', $this->session->get('password::sessioncredentials/credentials'));
		$this->assertSame('admin-app-password', $this->session->get('app_password'));
		$this->assertSame('admin-private-key', $this->session->get('privateKey'));
		$this->assertFalse($this->util->isImpersonating());
		foreach ([Util::SESSION_PARKED_TOKEN, Util::SESSION_IDENTITY_STASH, Util::SESSION_START,
			Util::SESSION_TOKEN_WATERMARK, Util::SESSION_PRIVATE_KEY, Util::SESSION_ENCRYPTION_INITIALIZED] as $key) {
			$this->assertNull($this->session->get($key), $key);
		}
	}

	public static function failedStopProvider(): array {
		return [
			'impersonator deleted' => ['deleted'],
			'impersonator disabled' => ['disabled'],
			'parked token revoked' => ['revoked'],
			'impersonated session revoked' => ['session-revoked'],
		];
	}

	/**
	 * @dataProvider failedStopProvider
	 */
	public function testStopImpersonationFailsClosed(string $case): void {
		$admin = $this->loggedInAdmin();
		$this->impersonating($admin, $this->user('alice'));
		if ($case === 'deleted') {
			$this->userManager->method('get')->willReturn(null);
		} elseif ($case === 'disabled') {
			$this->userManager->method('get')->willReturn($this->user('admin', false));
		} elseif ($case === 'revoked') {
			$this->userManager->method('get')->willReturn($admin);
			unset($this->tokens['parked-secret']);
		} else {
			$this->userManager->method('get')->willReturn($admin);
			unset($this->tokens['session-2']);
		}

		$this->assertFalse($this->util->stopImpersonation());

		$this->assertFalse($this->util->isImpersonating());
		$this->assertSame([], $this->generated, 'no session token may be created for the impersonator');
		$this->assertNull($this->session->get('password::sessioncredentials/credentials'));
		$this->assertNull($this->session->get(Util::SESSION_PARKED_TOKEN));
		$this->assertArrayNotHasKey('parked-secret', $this->tokens);
	}

	public function testAppPasswordsMintedDuringImpersonationAreRevoked(): void {
		$admin = $this->loggedInAdmin();
		$alice = $this->user('alice');
		$this->addToken('alice-own', 'alice', 'alice', 'pw', 'Desktop', IToken::PERMANENT_TOKEN, 50);
		$this->impersonating($admin, $alice);
		// the watermark is alice's highest token id before the impersonation started
		$this->assertSame(50, $this->session->get(Util::SESSION_TOKEN_WATERMARK));
		$minted = $this->addToken('minted', 'alice', 'alice', null, 'evil', IToken::PERMANENT_TOKEN);
		$this->addToken('alice-new-own', 'alice', 'alice', 'pw', 'Laptop', IToken::PERMANENT_TOKEN);
		$this->addToken('alice-new-session', 'alice', 'alice', null, 'Browser', IToken::TEMPORARY_TOKEN);
		$this->userManager->method('get')->willReturn($admin);

		$revoked = [];
		$this->tokenProvider->method('invalidateTokenById')->willReturnCallback(function (IUser $user, $id) use (&$revoked) {
			$revoked[] = [$user->getUID(), $id];
		});
		$this->logger->expects($this->atLeastOnce())->method('warning');

		$this->assertTrue($this->util->stopImpersonation());
		$this->assertSame([['alice', $minted->getId()]], $revoked);
	}

	public function testEndImpersonation(): void {
		$admin = $this->loggedInAdmin();
		$this->impersonating($admin, $this->user('alice'));

		$this->util->endImpersonation();

		$this->assertFalse($this->util->isImpersonating());
		$this->assertContains('parked-secret', $this->invalidated);
		$this->assertNull($this->session->get('password::sessioncredentials/credentials'));
		$this->assertNull($this->session->get('app_password'));
		$this->assertNull($this->session->get(Util::SESSION_PRIVATE_KEY));
	}

	public function testTouchParkedToken(): void {
		$admin = $this->loggedInAdmin();
		$this->impersonating($admin, $this->user('alice'));
		$this->userManager->expects($this->never())->method('checkPassword');
		$this->tokenProvider->expects($this->once())->method('updateTokenActivity')
			->with($this->tokens['parked-secret']);
		$this->assertTrue($this->util->touchParkedToken());

		unset($this->tokens['parked-secret']);
		$this->assertFalse($this->util->touchParkedToken());
	}

	public function testParkedPasswordIsRecheckedAfterTheTimeout(): void {
		$admin = $this->loggedInAdmin();
		$this->impersonating($admin, $this->user('alice'));
		$this->tokens['parked-secret']->setLastCheck(\time() - 3600);
		$this->userManager->expects($this->once())->method('checkPassword')
			->with('admin@example.com', 'admin-password')->willReturn($admin);
		$this->tokenProvider->expects($this->once())->method('updateToken');
		$this->assertTrue($this->util->touchParkedToken());
		$this->assertGreaterThan(\time() - 60, $this->tokens['parked-secret']->getLastCheck());
	}

	public function testChangedImpersonatorPasswordEndsTheParkedSession(): void {
		$admin = $this->loggedInAdmin();
		$this->impersonating($admin, $this->user('alice'));
		$this->tokens['parked-secret']->setLastCheck(\time() - 3600);
		$this->userManager->method('checkPassword')->willReturn(false);
		$this->assertFalse($this->util->touchParkedToken());
		$this->assertArrayNotHasKey('parked-secret', $this->tokens);
	}

	public function testSigningKeyCreatedDuringImpersonationIsRemoved(): void {
		$admin = $this->loggedInAdmin();
		$this->impersonating($admin, $this->user('alice'));
		$this->assertFalse($this->session->get(Util::SESSION_SIGNING_KEY_EXISTED));
		$this->userValues['alice/core/signing-key'] = 'created-while-impersonating';
		$this->userManager->method('get')->willReturn($admin);
		$this->assertTrue($this->util->stopImpersonation());
		$this->assertArrayNotHasKey('alice/core/signing-key', $this->userValues);
	}

	public function testExistingSigningKeyIsKept(): void {
		$this->userValues['alice/core/signing-key'] = 'existing';
		$admin = $this->loggedInAdmin();
		$this->impersonating($admin, $this->user('alice'));
		$this->util->endImpersonation();
		$this->assertSame('existing', $this->userValues['alice/core/signing-key']);
	}

	public function testFailedSwitchIsRolledBackAndLoggedOut(): void {
		$admin = $this->loggedInAdmin();
		$this->tokenProvider->method('getTokenByUser')->willReturn([]);
		$this->csrfTokenManager->method('refreshToken')->willThrowException(new \RuntimeException('boom'));
		$this->userSession->expects($this->once())->method('logout');
		try {
			$this->util->startImpersonation($this->user('alice'), $admin);
			$this->fail('exception expected');
		} catch (\RuntimeException $e) {
			$this->assertSame('boom', $e->getPrevious()->getMessage());
		}
		$this->assertFalse($this->util->isImpersonating());
		$this->assertArrayNotHasKey('parked-secret', $this->tokens);
		$this->assertNull($this->session->get(Util::SESSION_PARKED_TOKEN));
	}

	public function testTouchParkedTokenOfAnotherUser(): void {
		$admin = $this->loggedInAdmin();
		$this->impersonating($admin, $this->user('alice'));
		$this->tokens['parked-secret']->setUid('mallory');
		$this->assertFalse($this->util->touchParkedToken());
	}

	public function testImpersonationTokenName(): void {
		$this->assertSame('Impersonated by admin', Util::impersonationTokenName('admin'));
		$this->assertSame(120, \mb_strlen(Util::impersonationTokenName(\str_repeat('x', 200))));
	}
}
