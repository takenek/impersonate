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
use OCA\Impersonate\ActiveImpersonations;
use OCA\Impersonate\AuditTrail;
use OCA\Impersonate\CredentialCleanup;
use OCA\Impersonate\Policy;
use OCA\Impersonate\RefusedException;
use OCA\Impersonate\Tests\Unit\Support\ArraySession;
use OCA\Impersonate\Util;
use OCP\BackgroundJob\IJobList;
use OCP\IConfig;
use OCP\IDBConnection;
use OCP\ILogger;
use OCP\IUser;
use OCP\IUserManager;
use OCP\Notification\IManager;
use OCP\Notification\INotification;
use OCP\Security\ISecureRandom;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\EventDispatcher\GenericEvent;
use Test\TestCase;

/**
 * Util with its real collaborators (ActiveImpersonations, CredentialCleanup,
 * AuditTrail) on top of mocked platform services.
 */
class UtilTest extends TestCase {
	/** id of the record of the impersonation the tests start (16 characters a-z0-9) */
	private const RECORD = 'rrrrrrrrrrrrrrrr';

	/** @var ArraySession */
	private $session;
	/** @var Session|MockObject */
	private $userSession;
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
	/** @var IJobList|MockObject */
	private $jobList;
	/** @var ActiveImpersonations */
	private $registry;
	/** @var Policy|MockObject */
	private $policy;
	/** @var bool app config "allow_start_with_credentials" */
	private $allowStartWithCredentials = false;
	/** @var array<string, string> user values "uid/app/key" */
	private $userValues = [];
	/** @var array<string, string> app values of the app "impersonate" */
	private $appValues = [];
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
	/** @var array[] [uid, token id] of invalidateTokenById() calls */
	private $revokedById = [];
	/** @var array[] [event name, arguments] */
	private $events = [];
	/** @var int number of notifications sent */
	private $notifications = 0;
	/** @var int auto increment for token ids */
	private $nextId = 100;
	/** @var array<string, \Throwable> uid => what generateToken() throws for a token of that user */
	private $failTokenFor = [];

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
				if (isset($this->failTokenFor[$uid])) {
					throw $this->failTokenFor[$uid];
				}
				$this->generated[] = [$token, $uid, $loginName, $password, $name, $type];
				$this->addToken($token, $uid, $loginName, $password, $name, $type);
				return $this->tokens[$token];
			}
		);
		$this->tokenProvider->method('invalidateToken')->willReturnCallback(function ($token) {
			$this->invalidated[] = $token;
			unset($this->tokens[$token]);
		});
		$this->tokenProvider->method('getTokenByUser')->willReturnCallback(function (IUser $user) {
			return \array_values(\array_filter($this->tokens, function (DefaultToken $t) use ($user) {
				return $t->getUID() === $user->getUID();
			}));
		});
		$this->tokenProvider->method('invalidateTokenById')->willReturnCallback(function (IUser $user, $id) {
			$this->revokedById[] = [$user->getUID(), $id];
			foreach ($this->tokens as $key => $token) {
				if ($token->getId() === $id && $token->getUID() === $user->getUID()) {
					unset($this->tokens[$key]);
				}
			}
		});
		$this->userManager = $this->createMock(IUserManager::class);
		$this->secureRandom = $this->createMock(ISecureRandom::class);
		$this->secureRandom->method('generate')->willReturnCallback(function ($length) {
			// 64 characters: the secret of the parked token; 16: the id of a record
			return $length === 64 ? 'parked-secret' : self::RECORD;
		});
		$this->csrfTokenManager = $this->createMock(CsrfTokenManager::class);
		$this->logger = $this->createMock(ILogger::class);
		$this->config = $this->createMock(IConfig::class);
		$this->config->method('getAppValue')->willReturnCallback(function ($app, $key, $default = '') {
			return $app === 'impersonate' ? ($this->appValues[$key] ?? $default) : $default;
		});
		$this->config->method('setAppValue')->willReturnCallback(function ($app, $key, $value) {
			$this->appValues[$key] = $value;
		});
		$this->config->method('deleteAppValue')->willReturnCallback(function ($app, $key) {
			unset($this->appValues[$key]);
		});
		$this->config->method('getAppKeys')->willReturnCallback(function () {
			return \array_keys($this->appValues);
		});
		$this->config->method('getUserValue')->willReturnCallback(function ($uid, $app, $key, $default = '') {
			return $this->userValues["$uid/$app/$key"] ?? $default;
		});
		$this->config->method('deleteUserValue')->willReturnCallback(function ($uid, $app, $key) {
			unset($this->userValues["$uid/$app/$key"]);
		});
		$eventDispatcher = $this->createMock(EventDispatcherInterface::class);
		$eventDispatcher->method('dispatch')->willReturnCallback(function (GenericEvent $event, $name) {
			$this->events[] = [$name, $event->getArguments()];
			return $event;
		});
		$notification = $this->createMock(INotification::class);
		foreach (['setApp', 'setUser', 'setDateTime', 'setObject', 'setSubject'] as $setter) {
			$notification->method($setter)->willReturnSelf();
		}
		$notificationManager = $this->createMock(IManager::class);
		$notificationManager->method('createNotification')->willReturn($notification);
		$notificationManager->method('notify')->willReturnCallback(function () {
			$this->notifications++;
		});
		$this->jobList = $this->createMock(IJobList::class);
		$auditTrail = new AuditTrail($eventDispatcher, $notificationManager, $this->logger);
		$this->registry = new ActiveImpersonations(
			$this->config,
			$this->secureRandom,
			$this->jobList,
			$this->createMock(IDBConnection::class),
			$this->logger
		);
		$this->policy = $this->createMock(Policy::class);
		$this->policy->method('allowsStartWithCredentials')->willReturnCallback(function () {
			return $this->allowStartWithCredentials;
		});
		$this->util = new Util(
			$this->session,
			$this->userSession,
			$this->tokenProvider,
			$this->userManager,
			$this->secureRandom,
			$this->csrfTokenManager,
			$this->logger,
			$this->config,
			$this->registry,
			new CredentialCleanup($this->tokenProvider, $this->config, $auditTrail, $this->logger),
			$auditTrail,
			$this->policy
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
			'privateKey' => 'admin-private-key',
			'encryptionInitialized' => 2,
			'requesttoken' => 'csrf',
		];
		$this->addToken('session-1', 'admin', 'admin@example.com', 'admin-password', 'Firefox', IToken::TEMPORARY_TOKEN, 10);
		return $admin;
	}

	/**
	 * @return array[] arguments of the dispatched events with this name
	 */
	private function events(string $name): array {
		return \array_values(\array_map(function (array $event) {
			return $event[1];
		}, \array_filter($this->events, function (array $event) use ($name) {
			return $event[0] === $name;
		})));
	}

	/**
	 * @return array<string, mixed>|null the record of the impersonation the tests start
	 */
	private function record(): ?array {
		return $this->registry->get(self::RECORD);
	}

	public function testStartImpersonation(): void {
		$admin = $this->loggedInAdmin();
		$alice = $this->user('alice');
		$this->addToken('alice-old', 'alice', 'alice', 'pw', 'Phone', IToken::PERMANENT_TOKEN, 41);
		$this->csrfTokenManager->expects($this->once())->method('refreshToken');
		$this->jobList->method('has')->willReturn(false);
		$this->jobList->expects($this->once())->method('add')->with(\OCA\Impersonate\BackgroundJob\Reconcile::class);

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
		$this->assertSame('alice', $this->util->getTargetUid());
		$this->assertEqualsWithDelta(\time(), $this->util->getStartTime(), 5);
		$this->assertSame('alice', $this->session->get('loginname'));
		$this->assertNull($this->session->get('password::sessioncredentials/credentials'), 'impersonator credentials must not stay active');
		$this->assertNull($this->session->get('app_password'));
		$this->assertSame('parked-secret', $this->session->get(Util::SESSION_PARKED_TOKEN));
		// tokens are numbered in the order they are created: what alice gets from now on is above the session token
		$tokenId = $this->tokens['session-2']->getId();
		$this->assertGreaterThan(41, $tokenId);
		$this->assertSame($tokenId, $this->session->get(Util::SESSION_TOKEN_WATERMARK));
		$this->assertSame($tokenId, $this->session->get(Util::SESSION_TOKEN_ID));
		$this->assertSame(
			[
				'loginname' => 'admin@example.com',
				'password::sessioncredentials/credentials' => 'encrypted-admin-credentials',
			],
			\json_decode($this->session->get(Util::SESSION_IDENTITY_STASH), true)
		);
		// encryption keys are kept active (master key) and copied for the way back
		$this->assertSame('admin-private-key', $this->session->get('privateKey'));
		$this->assertSame('admin-private-key', $this->session->get(Util::SESSION_PRIVATE_KEY));
		$this->assertSame(2, $this->session->get(Util::SESSION_ENCRYPTION_INITIALIZED));
		// the server side record of the impersonation
		$this->assertSame(self::RECORD, $this->session->get(Util::SESSION_RECORD));
		$record = $this->record();
		$this->assertSame('admin', $record['impersonator']);
		$this->assertSame('alice', $record['target']);
		$this->assertSame($tokenId, $record['token']);
		$this->assertFalse($record['signingKey']);
		$this->assertSame($this->util->getStartTime(), $record['start']);
		// the start event belongs to the controller, nothing ended
		$this->assertSame([], $this->events);
	}

	public function testStartWithoutASessionTokenIsRefusedAndChangesNothing(): void {
		// e.g. a request that is only authenticated by HTTP Basic credentials or an app password
		$admin = $this->loggedInAdmin();
		unset($this->tokens['session-1']);
		$before = $this->session->data;
		$this->userSession->expects($this->never())->method('logout');

		try {
			$this->util->startImpersonation($this->user('alice'), $admin);
			$this->fail('exception expected');
		} catch (RefusedException $e) {
			$this->assertStringContainsString('interactive session', $e->getMessage());
		}

		$this->assertSame([], $this->generated, 'no token may be created');
		$this->assertSame([], $this->invalidated);
		$this->assertSame([], $this->session->regenerated);
		$this->assertSame($before, $this->session->data);
		$this->assertSame($admin, $this->sessionUser);
		$this->assertFalse($this->util->isImpersonating());
		$this->assertSame([], $this->appValues, 'no record');
	}

	public function testStartWithASessionTokenOfAnotherUserIsRefused(): void {
		$admin = $this->loggedInAdmin();
		$this->tokens['session-1']->setUid('mallory');
		$before = $this->session->data;

		try {
			$this->util->startImpersonation($this->user('alice'), $admin);
			$this->fail('exception expected');
		} catch (RefusedException $e) {
			$this->assertStringContainsString('does not belong', $e->getMessage());
		}

		$this->assertSame([], $this->generated);
		$this->assertSame($before, $this->session->data);
		$this->assertFalse($this->util->isImpersonating());
	}

	public static function credentialSessionProvider(): array {
		return [
			'logged in with a token (e.g. an app password)' => ['app_password', 'the-app-password'],
			'authenticated with HTTP Basic credentials' => ['AUTHENTICATED_TO_DAV_BACKEND', 'admin'],
		];
	}

	/**
	 * The platform gives a request with credentials a session with a session token of its
	 * own once it carries a cookie: a later request of that session brings no credentials
	 * anymore, but the session says how it came about.
	 *
	 * @dataProvider credentialSessionProvider
	 */
	public function testStartFromASessionThatARequestWithCredentialsCreatedIsRefused(string $marker, string $value): void {
		$admin = $this->loggedInAdmin();
		$this->session->set($marker, $value);
		$before = $this->session->data;
		try {
			$this->util->startImpersonation($this->user('alice'), $admin);
			$this->fail('exception expected');
		} catch (RefusedException $e) {
			$this->assertStringContainsString('interactive session', $e->getMessage());
		}
		$this->assertSame([], $this->generated);
		$this->assertSame($before, $this->session->data);
		$this->assertArrayHasKey('session-1', $this->tokens);

		// unless the operator accepted such starts (authentication by a proxy or the web server)
		$this->allowStartWithCredentials = true;
		$this->util->startImpersonation($this->user('alice'), $admin);
		$this->assertTrue($this->util->isImpersonating());
		// the marker belongs to the identity of the impersonator: out of the way and back again
		$this->assertNull($this->session->get($marker));
		$this->userManager->method('get')->willReturn($admin);
		$this->assertTrue($this->util->stopImpersonation());
		$this->assertSame($value, $this->session->get($marker));
	}

	public function testStartFromAPasswordlessSessionParksAPasswordlessToken(): void {
		// e.g. single sign-on: nothing to re-check, such an impersonation is bounded by the maximum duration
		$admin = $this->loggedInAdmin();
		$this->passwords['session-1'] = null;

		$this->util->startImpersonation($this->user('alice'), $admin);

		$this->assertSame(['parked-secret', 'admin', 'admin@example.com', null, 'Firefox', IToken::TEMPORARY_TOKEN], $this->generated[0]);
		$this->assertTrue($this->util->isImpersonating());
	}

	public function testAValueThatCanNotBeStashedStopsTheStartBeforeAnythingChanges(): void {
		$admin = $this->loggedInAdmin();
		// not valid UTF-8: can not be encoded as JSON
		$this->session->set('password::sessioncredentials/credentials', "\xB1\x31");
		$before = $this->session->data;
		$this->userSession->expects($this->never())->method('logout');

		try {
			$this->util->startImpersonation($this->user('alice'), $admin);
			$this->fail('exception expected');
		} catch (\JsonException $e) {
		}

		$this->assertSame([], $this->generated);
		$this->assertSame([], $this->invalidated);
		$this->assertSame($before, $this->session->data, 'the session of the impersonator stays as it was');
		$this->assertArrayHasKey('session-1', $this->tokens);
	}

	public function testNestedImpersonationIsRejected(): void {
		$admin = $this->loggedInAdmin();
		$this->session->set(Util::SESSION_IMPERSONATOR, 'someone');
		$this->expectException(\LogicException::class);
		$this->util->startImpersonation($this->user('alice'), $admin);
	}

	private function impersonating(IUser $admin, IUser $alice): void {
		$this->util->startImpersonation($alice, $admin);
		$this->generated = [];
		$this->invalidated = [];
		$this->userManager->method('get')->willReturnCallback(function ($uid) use ($admin, $alice) {
			return ['admin' => $admin, 'alice' => $alice][$uid] ?? null;
		});
		// the impersonated session writes its own values
		$this->session->set('password::sessioncredentials/credentials', 'alice-credentials');
		$this->session->set('app_password', 'alice-app-password');
	}

	public function testStopImpersonationRestoresTheImpersonator(): void {
		$admin = $this->loggedInAdmin();
		$alice = $this->user('alice');
		$this->impersonating($admin, $alice);
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
		$this->assertNull($this->session->get('app_password'), 'what the impersonated session stored does not stay');
		$this->assertSame('admin-private-key', $this->session->get('privateKey'));
		$this->assertFalse($this->util->isImpersonating());
		foreach ([Util::SESSION_PARKED_TOKEN, Util::SESSION_IDENTITY_STASH, Util::SESSION_START, Util::SESSION_TARGET,
			Util::SESSION_TOKEN_WATERMARK, Util::SESSION_PRIVATE_KEY, Util::SESSION_ENCRYPTION_INITIALIZED,
			Util::SESSION_RECORD, Util::SESSION_SIGNING_KEY_EXISTED, Util::SESSION_TOKEN_ID] as $key) {
			$this->assertNull($this->session->get($key), $key);
		}
		$this->assertNull($this->record(), 'the record is closed');
		$this->assertSame(
			[['impersonator' => 'admin', 'targetUser' => 'alice', 'reason' => Util::REASON_RETURNED]],
			$this->events(AuditTrail::EVENT_END),
			'the end is announced exactly once'
		);
	}

	public static function failedStopProvider(): array {
		return [
			'impersonator deleted' => ['deleted'],
			'impersonator disabled' => ['disabled'],
			'parked token revoked' => ['revoked'],
			'impersonated session revoked' => ['session-revoked'],
			'another user in the session' => ['other-user'],
			'already ended by the reconcile job' => ['closed-elsewhere'],
		];
	}

	/**
	 * @dataProvider failedStopProvider
	 */
	public function testStopImpersonationFailsClosed(string $case): void {
		$admin = $this->loggedInAdmin();
		$alice = $this->user('alice');
		if ($case === 'deleted') {
			$this->util->startImpersonation($alice, $admin);
			$this->userManager->method('get')->willReturnCallback(function ($uid) use ($alice) {
				return $uid === 'alice' ? $alice : null;
			});
		} elseif ($case === 'disabled') {
			$this->util->startImpersonation($alice, $admin);
			$this->userManager->method('get')->willReturnCallback(function ($uid) use ($alice) {
				return $uid === 'alice' ? $alice : $this->user('admin', false);
			});
		} else {
			$this->impersonating($admin, $alice);
		}
		$this->generated = [];
		if ($case === 'revoked') {
			unset($this->tokens['parked-secret']);
		} elseif ($case === 'session-revoked') {
			unset($this->tokens['session-2']);
		} elseif ($case === 'other-user') {
			$this->sessionUser = $this->user('bob');
			$this->tokens['session-2']->setUid('bob');
		} elseif ($case === 'closed-elsewhere') {
			$this->registry->close(self::RECORD);
		}

		$this->assertFalse($this->util->stopImpersonation());

		$this->assertFalse($this->util->isImpersonating());
		$this->assertSame([], $this->generated, 'no session token may be created for the impersonator');
		$this->assertNull($this->session->get('password::sessioncredentials/credentials'));
		$this->assertNull($this->session->get(Util::SESSION_PARKED_TOKEN));
		$this->assertArrayNotHasKey('parked-secret', $this->tokens);
		$this->assertArrayNotHasKey('session-2', $this->tokens, 'the impersonated session can not go on');
		$this->assertNull($this->record());
		if ($case === 'closed-elsewhere') {
			$this->assertSame([], $this->events(AuditTrail::EVENT_END), 'it was announced where it was closed');
		} else {
			$this->assertSame(
				[['impersonator' => 'admin', 'targetUser' => 'alice', 'reason' => Util::REASON_SWITCH_BACK_FAILED]],
				$this->events(AuditTrail::EVENT_END)
			);
		}
	}

	public function testAFailureWhileSwitchingBackEndsTheImpersonation(): void {
		$admin = $this->loggedInAdmin();
		$this->impersonating($admin, $this->user('alice'));
		// the token of the restored session can not be created
		$this->failTokenFor['admin'] = new \RuntimeException('token backend down');
		$this->logger->expects($this->atLeastOnce())->method('logException');

		$this->assertFalse($this->util->stopImpersonation(), 'the caller lets the logout proceed');

		$this->assertFalse($this->util->isImpersonating());
		$this->assertArrayNotHasKey('parked-secret', $this->tokens);
		$this->assertArrayNotHasKey('session-2', $this->tokens);
		$this->assertSame([], $this->generated);
		foreach (Util::IDENTITY_KEYS as $key) {
			$this->assertNull($this->session->get($key), "no half restored session: $key");
		}
		$this->assertNull($this->session->get(Util::SESSION_PRIVATE_KEY));
		$this->assertNull($this->record());
		$this->assertSame(
			[['impersonator' => 'admin', 'targetUser' => 'alice', 'reason' => Util::REASON_SWITCH_BACK_FAILED]],
			$this->events(AuditTrail::EVENT_END)
		);
	}

	public function testAnErrorInsteadOfAnExceptionWhileSwitchingBackIsHandledAsWell(): void {
		$admin = $this->loggedInAdmin();
		$this->impersonating($admin, $this->user('alice'));
		$this->failTokenFor['admin'] = new \TypeError('unexpected');

		$this->assertFalse($this->util->stopImpersonation());
		$this->assertFalse($this->util->isImpersonating());
	}

	public function testWhatTheImpersonatedSessionCouldHaveCreatedIsRevokedWhenItEnds(): void {
		$admin = $this->loggedInAdmin();
		$alice = $this->user('alice');
		// older than the impersonation, and without a stored password: stays
		$older = $this->addToken('alice-own', 'alice', 'alice', null, 'Desktop', IToken::PERMANENT_TOKEN, 50);
		$this->impersonating($admin, $alice);
		// an app password created from the impersonated session
		$minted = $this->addToken('minted', 'alice', 'alice', null, 'evil', IToken::PERMANENT_TOKEN);
		// what alice created herself with her password in that time
		$ownAppPassword = $this->addToken('alice-new-own', 'alice', 'alice', 'pw', 'Laptop', IToken::PERMANENT_TOKEN);
		$ownSession = $this->addToken('alice-own-session', 'alice', 'alice', 'pw', 'Firefox', IToken::TEMPORARY_TOKEN);
		// a session that was logged in with the session id of the impersonation as its credential
		$derived = $this->addToken('derived-session', 'alice', 'alice', null, 'curl', IToken::TEMPORARY_TOKEN);
		$this->logger->expects($this->atLeastOnce())->method('warning');

		$this->assertTrue($this->util->stopImpersonation());

		$this->assertSame([['alice', $minted->getId()], ['alice', $derived->getId()]], $this->revokedById);
		$this->assertContains($older, $this->tokens);
		$this->assertContains($ownAppPassword, $this->tokens);
		$this->assertContains($ownSession, $this->tokens);
		// the account owner and audit apps learn about it
		$this->assertSame(
			[
				['targetUser' => 'alice', 'credential' => 'evil', 'impersonator' => 'admin'],
				['targetUser' => 'alice', 'credential' => 'session curl', 'impersonator' => 'admin'],
			],
			$this->events(AuditTrail::EVENT_CREDENTIAL_REVOKED)
		);
		$this->assertSame(2, $this->notifications);
	}

	public function testTheCleanupWorksOnTheImpersonatedUserEvenIfTheSessionHoldsAnotherUser(): void {
		$admin = $this->loggedInAdmin();
		$alice = $this->user('alice');
		$this->impersonating($admin, $alice);
		$minted = $this->addToken('minted', 'alice', 'alice', null, 'evil', IToken::PERMANENT_TOKEN);
		$adminOwn = $this->addToken('admin-own', 'admin', 'admin', null, 'CLI', IToken::PERMANENT_TOKEN);
		// e.g. a switch back that failed after the user of the session was set
		$this->sessionUser = $admin;

		$tokenId = $this->tokens['session-2']->getId();

		$this->util->endImpersonation('test');

		$this->assertSame([['alice', $tokenId], ['alice', $minted->getId()]], $this->revokedById);
		$this->assertContains($adminOwn, $this->tokens, 'tokens of the impersonator are not touched');
	}

	public function testEndImpersonation(): void {
		$admin = $this->loggedInAdmin();
		$this->impersonating($admin, $this->user('alice'));

		$this->util->endImpersonation('the reason');

		$this->assertFalse($this->util->isImpersonating());
		$this->assertContains('parked-secret', $this->invalidated);
		$this->assertContains('session-2', $this->invalidated, 'the impersonated session has no valid token anymore');
		$this->assertNull($this->session->get('password::sessioncredentials/credentials'));
		$this->assertNull($this->session->get('app_password'));
		$this->assertNull($this->session->get(Util::SESSION_PRIVATE_KEY));
		$this->assertNull($this->record());
		$this->assertSame(
			[['impersonator' => 'admin', 'targetUser' => 'alice', 'reason' => 'the reason']],
			$this->events(AuditTrail::EVENT_END)
		);

		// ending again does nothing and announces nothing
		$this->util->endImpersonation('again');
		$this->assertCount(1, $this->events(AuditTrail::EVENT_END));
	}

	public function testEndImpersonationNeverThrowsAndKeepsTheRecordForARetry(): void {
		$admin = $this->loggedInAdmin();
		$this->impersonating($admin, $this->user('alice'));
		// every token operation fails from now on
		$failing = $this->createMock(DefaultTokenProvider::class);
		foreach (['getTokenByUser', 'invalidateToken', 'invalidateTokenById', 'getToken'] as $method) {
			$failing->method($method)->willThrowException(new \RuntimeException('token backend down'));
		}
		$auditTrail = new AuditTrail(
			$dispatcher = $this->createMock(EventDispatcherInterface::class),
			$this->createMock(IManager::class),
			$this->logger
		);
		$dispatcher->expects($this->once())->method('dispatch')->willReturnArgument(0);
		$util = new Util(
			$this->session,
			$this->userSession,
			$failing,
			$this->userManager,
			$this->secureRandom,
			$this->csrfTokenManager,
			$this->logger,
			$this->config,
			$this->registry,
			new CredentialCleanup($failing, $this->config, $auditTrail, $this->logger),
			$auditTrail,
			$this->policy
		);

		$util->endImpersonation('the reason');

		$this->assertFalse($util->isImpersonating(), 'the session is not an impersonation anymore');
		$record = $this->record();
		$this->assertNotNull($record, 'the reconcile job retries the cleanup, and the record keeps the token known');
		$this->assertTrue($record['pending']);
		$this->assertEqualsWithDelta(\time(), $record['ended'], 5);
		$this->assertArrayNotHasKey('ceiling', $record, 'the tokens could not even be listed');
	}

	public function testEndImpersonationAfterItWasEndedElsewhereLeavesLaterCredentialsAlone(): void {
		$admin = $this->loggedInAdmin();
		$alice = $this->user('alice');
		$this->impersonating($admin, $alice);
		$tokenId = $this->tokens['session-2']->getId();
		// The job ended it: token revoked, cleanup done, record closed. Hours later the
		// impersonator clicks in the old tab. What alice created since is hers.
		unset($this->tokens['session-2']);
		$this->registry->close(self::RECORD);
		$own = $this->addToken('alice-own-later', 'alice', 'alice', null, 'Own', IToken::PERMANENT_TOKEN);
		$this->userValues['alice/core/signing-key'] = 'created by alice later';

		$this->assertTrue($this->util->hasEndedElsewhere());
		$this->util->endImpersonation('logout');

		$this->assertFalse($this->util->isImpersonating());
		$this->assertContains($own, $this->tokens, 'no second cleanup');
		$this->assertSame('created by alice later', $this->userValues['alice/core/signing-key']);
		$this->assertSame(0, $this->notifications);
		$this->assertSame([['alice', $tokenId]], $this->revokedById, 'only the token of the impersonation, once more');
		$this->assertSame([], $this->events(AuditTrail::EVENT_END), 'no second announcement');
		$this->assertContains('parked-secret', $this->invalidated);
		$this->assertNull($this->record());
	}

	public function testTheSessionOfAnotherImpersonationOfTheSameUserSurvivesTheCleanup(): void {
		$admin = $this->loggedInAdmin();
		$alice = $this->user('alice');
		$this->impersonating($admin, $alice);
		// carol impersonates alice as well, a little later
		$other = $this->addToken('carols-impersonated-session', 'alice', 'alice', null, 'Impersonated by carol', IToken::TEMPORARY_TOKEN);
		$this->appValues['active_carolcarolcarol0'] = \json_encode([
			'impersonator' => 'carol', 'target' => 'alice', 'token' => $other->getId(), 'signingKey' => false, 'start' => \time(),
		]);
		$minted = $this->addToken('minted', 'alice', 'alice', null, 'evil', IToken::PERMANENT_TOKEN);

		$this->assertTrue($this->util->stopImpersonation());

		$this->assertSame([['alice', $minted->getId()]], $this->revokedById);
		$this->assertContains($other, $this->tokens, 'the other impersonation goes on');
		$this->assertSame(1, $this->notifications);
	}

	public function testASessionSwitchedByAnOlderVersionDoesNotReportItsOwnTokenAsARevokedCredential(): void {
		// its mark is the highest token id before the start, below its own session token
		$admin = $this->loggedInAdmin();
		$this->impersonating($admin, $this->user('alice'));
		$this->registry->close(self::RECORD);
		$this->session->remove(Util::SESSION_RECORD);
		$this->session->remove(Util::SESSION_TARGET);
		$this->session->remove(Util::SESSION_TOKEN_ID);
		$this->session->set(Util::SESSION_TOKEN_WATERMARK, 41);

		$this->util->endImpersonation('logout');

		$this->assertSame([], $this->revokedById, 'the session token ends with the session, not as a "revoked credential"');
		$this->assertSame([], $this->events(AuditTrail::EVENT_CREDENTIAL_REVOKED));
		$this->assertSame(0, $this->notifications);
		$this->assertArrayNotHasKey('session-2', $this->tokens);
	}

	public function testEndImpersonationAfterARecordWasClosedWhileItsSessionWasAliveCleansUp(): void {
		$admin = $this->loggedInAdmin();
		$alice = $this->user('alice');
		$this->impersonating($admin, $alice);
		$tokenId = $this->tokens['session-2']->getId();
		// the record is gone (e.g. it was unreadable and discarded), but the token was never revoked:
		// the session could act until now
		$this->registry->close(self::RECORD);
		$minted = $this->addToken('minted-afterwards', 'alice', 'alice', null, 'evil', IToken::PERMANENT_TOKEN);

		$this->util->endImpersonation('logout');

		$this->assertSame([['alice', $tokenId], ['alice', $minted->getId()]], $this->revokedById);
		$this->assertSame([], $this->events(AuditTrail::EVENT_END));
	}

	public function testTheEndRevokesTheTokenTheImpersonationWasStartedWithWhereverTheSessionIsNow(): void {
		// e.g. a failed login attempt inside the impersonated session gave the session a new id:
		// the session token "Impersonated by" is not the token of the current session id anymore
		$admin = $this->loggedInAdmin();
		$this->impersonating($admin, $this->user('alice'));
		$tokenId = $this->tokens['session-2']->getId();
		$this->session->id = 'session-after-a-failed-login';
		$this->assertFalse($this->util->isBoundToItsToken());

		$this->util->endImpersonation(Util::REASON_LOGOUT);

		$this->assertSame([['alice', $tokenId]], $this->revokedById);
		$this->assertArrayNotHasKey('session-2', $this->tokens, 'no valid, untracked token of alice is left');
		$this->assertNull($this->record());
	}

	public function testTheSessionIsBoundToTheTokenItWasStartedWith(): void {
		$admin = $this->loggedInAdmin();
		$this->assertTrue($this->util->isBoundToItsToken(), 'no impersonation: nothing to check');
		$this->impersonating($admin, $this->user('alice'));
		$this->assertTrue($this->util->isBoundToItsToken());
		$this->assertFalse($this->util->hasEndedElsewhere());
		$this->session->remove('app_password');
		$this->assertSame(['session-2'], $this->util->getSessionSecrets());
		$this->session->set('app_password', 'a-token-the-session-was-logged-in-with');
		$this->assertSame(['session-2', 'a-token-the-session-was-logged-in-with'], $this->util->getSessionSecrets());
		// another session token of the same user is not the one of the impersonation
		$this->addToken('another-session', 'alice', 'alice', 'pw', 'Firefox', IToken::TEMPORARY_TOKEN);
		$this->session->id = 'another-session';
		$this->assertFalse($this->util->isBoundToItsToken());
		// a record that only waits for its cleanup has ended
		$this->registry->markPending(self::RECORD, $this->record(), \time());
		$this->assertTrue($this->util->hasEndedElsewhere());
	}

	public function testNoSwitchBackFromASessionThatIsNotBoundToItsToken(): void {
		$admin = $this->loggedInAdmin();
		$this->impersonating($admin, $this->user('alice'));
		$tokenId = $this->tokens['session-2']->getId();
		$this->addToken('another-session', 'alice', 'alice', 'pw', 'Firefox', IToken::TEMPORARY_TOKEN);
		$this->session->id = 'another-session';

		$this->assertFalse($this->util->stopImpersonation());

		$this->assertSame([], $this->generated, 'no session for the impersonator');
		$this->assertContains(['alice', $tokenId], $this->revokedById);
		$this->assertArrayNotHasKey('another-session', $this->tokens, 'the session it happened in is ended as well');
		$this->assertFalse($this->util->isImpersonating());
	}

	public function testAnImpersonatedUserThatCanNotBeLoadedLeavesTheEndToTheReconcileJob(): void {
		// deleted, or its backend does not answer: then its token could not be revoked by id
		$admin = $this->loggedInAdmin();
		$this->util->startImpersonation($this->user('alice'), $admin);
		$this->userManager->method('get')->willReturn(null);

		$this->util->endImpersonation(Util::REASON_LOGOUT);

		$this->assertFalse($this->util->isImpersonating());
		$record = $this->record();
		$this->assertTrue($record['pending'], 'the record keeps the token known until the job has dealt with it');
		$this->assertFalse($record['signingKey'], 'a cleanup that never ran has dealt with nothing');
		$this->assertArrayNotHasKey('ceiling', $record);
		$this->assertCount(1, $this->events(AuditTrail::EVENT_END));
	}

	public function testSessionsSwitchedByAnOlderVersionStillEnd(): void {
		// no record and no recorded target in the session
		$admin = $this->loggedInAdmin();
		$alice = $this->user('alice');
		$this->impersonating($admin, $alice);
		$this->registry->close(self::RECORD);
		$this->session->remove(Util::SESSION_RECORD);
		$this->session->remove(Util::SESSION_TARGET);
		$this->session->remove(Util::SESSION_TOKEN_ID);
		$this->assertTrue($this->util->isBoundToItsToken(), 'nothing recorded to compare with');
		$this->assertFalse($this->util->hasEndedElsewhere());
		$minted = $this->addToken('minted', 'alice', 'alice', null, 'evil', IToken::PERMANENT_TOKEN);

		$this->util->endImpersonation('logout');

		$this->assertSame([['alice', $minted->getId()]], $this->revokedById);
		$this->assertSame(
			[['impersonator' => 'admin', 'targetUser' => 'alice', 'reason' => 'logout']],
			$this->events(AuditTrail::EVENT_END)
		);
	}

	public function testTheEncryptionStateIsRestoredExactly(): void {
		$admin = $this->loggedInAdmin();
		// the impersonator's session has no encryption state
		$this->session->remove('privateKey');
		$this->session->remove('encryptionInitialized');
		$this->impersonating($admin, $this->user('alice'));
		// the impersonated session got one
		$this->session->set('privateKey', 'key-set-while-impersonating');
		$this->session->set('encryptionInitialized', 2);

		$this->assertTrue($this->util->stopImpersonation());

		$this->assertNull($this->session->get('privateKey'), 'a key set during the impersonation does not stay');
		$this->assertNull($this->session->get('encryptionInitialized'));
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
		$this->assertTrue($this->util->stopImpersonation());
		$this->assertArrayNotHasKey('alice/core/signing-key', $this->userValues);
	}

	public function testExistingSigningKeyIsKept(): void {
		$this->userValues['alice/core/signing-key'] = 'existing';
		$admin = $this->loggedInAdmin();
		$this->impersonating($admin, $this->user('alice'));
		$this->assertTrue($this->record()['signingKey']);
		$this->util->endImpersonation('test');
		$this->assertSame('existing', $this->userValues['alice/core/signing-key']);
	}

	public function testFailedSwitchIsRolledBackAndLoggedOut(): void {
		$admin = $this->loggedInAdmin();
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
		$this->assertArrayNotHasKey('session-2', $this->tokens, 'the half switched session has no valid token');
		$this->assertNull($this->session->get(Util::SESSION_PARKED_TOKEN));
		$this->assertNull($this->session->get(Util::SESSION_TARGET));
		$this->assertNull($this->record(), 'no record of an impersonation that did not start');
		$this->assertSame([], $this->events(AuditTrail::EVENT_END), 'nothing started, nothing ended');
	}

	public function testAFailedSwitchWhoseTokenCanNotBeRevokedKeepsItsRecord(): void {
		$admin = $this->loggedInAdmin();
		$alice = $this->user('alice');
		$this->csrfTokenManager->method('refreshToken')->willThrowException(new \RuntimeException('boom'));
		// the token backend fails right after the token of the target session was created
		$failing = $this->createMock(DefaultTokenProvider::class);
		$failing->method('getToken')->willReturnCallback(function ($tokenId) {
			if (!isset($this->tokens[$tokenId])) {
				throw new InvalidTokenException();
			}
			return $this->tokens[$tokenId];
		});
		$failing->method('getPassword')->willReturn('admin-password');
		$failing->method('generateToken')->willReturnCallback(function ($token, $uid, $loginName, $password, $name, $type) {
			return $this->addToken($token, $uid, $loginName, $password, $name, $type);
		});
		$failing->method('invalidateToken')->willReturnCallback(function ($token) {
			if ($token !== 'session-1') {
				throw new \RuntimeException('token backend down');
			}
			unset($this->tokens[$token]);
		});
		$failing->method('invalidateTokenById')->willThrowException(new \RuntimeException('token backend down'));
		$failing->method('getTokenByUser')->willReturn([]);
		$auditTrail = new AuditTrail($this->createMock(EventDispatcherInterface::class), $this->createMock(IManager::class), $this->logger);
		$util = new Util(
			$this->session,
			$this->userSession,
			$failing,
			$this->userManager,
			$this->secureRandom,
			$this->csrfTokenManager,
			$this->logger,
			$this->config,
			$this->registry,
			new CredentialCleanup($failing, $this->config, $auditTrail, $this->logger),
			$auditTrail,
			$this->policy
		);
		try {
			$util->startImpersonation($alice, $admin);
			$this->fail('exception expected');
		} catch (\RuntimeException $e) {
		}
		$this->assertFalse($util->isImpersonating());
		$this->assertArrayHasKey('session-2', $this->tokens, 'the token of the half switched session could not be revoked');
		$record = $this->record();
		$this->assertNotNull($record, '... so its record stays: the guard knows the token, the reconcile job revokes it');
		$this->assertTrue($record['pending']);
		$this->assertSame($this->tokens['session-2']->getId(), $record['token']);
	}

	public function testAFailedSwitchLeavesNoUsableSessionEvenIfTheLogoutFails(): void {
		$admin = $this->loggedInAdmin();
		$this->csrfTokenManager->method('refreshToken')->willThrowException(new \RuntimeException('boom'));
		$this->userSession->method('logout')->willThrowException(new \RuntimeException('logout failed'));
		try {
			$this->util->startImpersonation($this->user('alice'), $admin);
			$this->fail('exception expected');
		} catch (\RuntimeException $e) {
		}
		$this->assertSame([], $this->tokens, 'neither the old, the parked nor the new session token is valid');
		$this->assertFalse($this->util->isImpersonating());
	}

	public function testTheImpersonationIsMarkedBeforeTheUserOfTheSessionChanges(): void {
		// a request that dies in between must leave a session the guard ends
		$admin = $this->loggedInAdmin();
		$marked = null;
		$this->userSession->method('setUser')->willReturnCallback(function ($user) use (&$marked) {
			$marked = $marked ?? [$this->session->get(Util::SESSION_IMPERSONATOR), $this->session->get(Util::SESSION_TARGET)];
			$this->sessionUser = $user;
		});
		$this->util->startImpersonation($this->user('alice'), $admin);
		$this->assertSame(['admin', 'alice'], $marked);
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
