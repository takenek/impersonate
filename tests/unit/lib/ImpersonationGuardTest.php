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

use OCA\Impersonate\ActiveImpersonations;
use OCA\Impersonate\CredentialCleanup;
use OCA\Impersonate\ImpersonationGuard;
use OCA\Impersonate\Policy;
use OCA\Impersonate\Reconciler;
use OCA\Impersonate\Util;
use OCP\ILogger;
use OCP\IRequest;
use OCP\IUser;
use OCP\IUserManager;
use OCP\IUserSession;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

class ImpersonationGuardTest extends TestCase {
	/** @var Util|MockObject */
	private $util;
	/** @var Policy|MockObject */
	private $policy;
	/** @var IUserSession|MockObject */
	private $userSession;
	/** @var IUserManager|MockObject */
	private $userManager;
	/** @var IRequest|MockObject */
	private $request;
	/** @var ILogger|MockObject */
	private $logger;
	/** @var ActiveImpersonations|MockObject */
	private $registry;
	/** @var CredentialCleanup|MockObject */
	private $cleanup;
	/** @var Reconciler|MockObject */
	private $reconciler;
	/** @var ImpersonationGuard */
	private $guard;
	/** @var bool the session is the one the impersonation was started in */
	private $bound = true;
	/** @var bool the record of the impersonation is gone or waits for its cleanup */
	private $endedElsewhere = false;
	/** @var array<string, array{id: int, uid: string}> secret => the token it belongs to */
	private $tokens = [];
	/** @var array request parameters */
	private $params = [];
	/** @var array */
	private $serverBackup;

	private const RECORD = ['impersonator' => 'admin', 'target' => 'alice', 'token' => 60, 'signingKey' => false, 'start' => 1700000000];

	/**
	 * A value in the shape of a session id of this PHP (the guard only looks up such request values)
	 */
	private static function sessionId(string $seed): string {
		$length = (int)\ini_get('session.sid_length');
		$length = $length >= 22 && $length <= 256 ? $length : 32;
		return \substr(\str_repeat(\md5($seed), 8), 0, $length);
	}

	protected function tearDown(): void {
		$_SERVER = $this->serverBackup;
		parent::tearDown();
	}

	protected function setUp(): void {
		parent::setUp();
		$this->serverBackup = $_SERVER;
		unset($_SERVER['PHP_AUTH_PW'], $_SERVER['PHP_AUTH_USER'], $_SERVER['REDIRECT_HTTP_AUTHORIZATION']);
		$this->util = $this->createMock(Util::class);
		$this->util->method('isBoundToItsToken')->willReturnCallback(function () {
			return $this->bound;
		});
		$this->util->method('hasEndedElsewhere')->willReturnCallback(function () {
			return $this->endedElsewhere;
		});
		$this->registry = $this->createMock(ActiveImpersonations::class);
		$this->cleanup = $this->createMock(CredentialCleanup::class);
		$this->cleanup->method('findToken')->willReturnCallback(function ($secret) {
			return $this->tokens[$secret] ?? null;
		});
		$this->reconciler = $this->createMock(Reconciler::class);
		$this->policy = $this->createMock(Policy::class);
		$this->userSession = $this->createMock(IUserSession::class);
		$this->userManager = $this->createMock(IUserManager::class);
		$this->request = $this->createMock(IRequest::class);
		$this->request->method('getParams')->willReturnCallback(function () {
			return $this->params;
		});
		$this->logger = $this->createMock(ILogger::class);
		$this->guard = new ImpersonationGuard(
			$this->util,
			$this->policy,
			$this->userSession,
			$this->userManager,
			$this->request,
			$this->logger,
			$this->registry,
			$this->cleanup,
			$this->reconciler
		);
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

	private function request(string $method, string $path): void {
		$this->request->method('getMethod')->willReturn($method);
		$this->request->method('getRawPathInfo')->willReturn($path);
		$this->request->method('getPathInfo')->willReturn(\rawurldecode($path));
	}

	/**
	 * admin impersonates alice, everything is in order
	 */
	private function validImpersonation(): void {
		$this->util->method('isImpersonating')->willReturn(true);
		$this->util->method('getImpersonatorUid')->willReturn('admin');
		$this->util->method('getTargetUid')->willReturn('alice');
		$this->util->method('getStartTime')->willReturn(\time());
		$this->util->method('touchParkedToken')->willReturn(true);
		$this->userSession->method('getUser')->willReturn($this->user('alice'));
		$this->userManager->method('get')->with('admin')->willReturn($this->user('admin'));
		$this->policy->method('check')->willReturn(null);
		$this->policy->method('hasExceededMaxDuration')->willReturn(false);
		$this->policy->method('getExtraForbiddenPrefixes')->willReturn([]);
	}

	public function testNothingToDoWithoutImpersonation(): void {
		$this->util->method('getImpersonatorUid')->willReturn(null);
		$this->userSession->expects($this->never())->method('logout');
		$this->assertTrue($this->guard->validate());
	}

	public function testValidImpersonation(): void {
		$this->util->method('getImpersonatorUid')->willReturn('admin');
		$this->util->method('getTargetUid')->willReturn('alice');
		$this->userSession->method('getUser')->willReturn($this->user('alice'));
		$this->userManager->method('get')->with('admin')->willReturn($this->user('admin'));
		$this->policy->method('check')->willReturn(null);
		$this->policy->method('hasExceededMaxDuration')->willReturn(false);
		$this->util->expects($this->once())->method('touchParkedToken')->willReturn(true);
		$this->util->expects($this->never())->method('endImpersonation');
		$this->userSession->expects($this->never())->method('logout');
		$this->assertTrue($this->guard->validate());
	}

	public static function invalidProvider(): array {
		return [
			'impersonator deleted' => [null, null, false, true, 'the impersonator does not exist anymore'],
			'impersonator disabled' => [false, null, false, true, 'the impersonator has been disabled'],
			'permission revoked' => [true, Policy::ERROR_CANNOT_IMPERSONATE, false, true, 'the impersonator is not allowed to impersonate this user anymore'],
			'maximum duration reached' => [true, null, true, true, 'the maximum duration of the impersonation was reached'],
			'parked session revoked' => [true, null, false, false, "the impersonator's own session was revoked or has expired"],
		];
	}

	/**
	 * @dataProvider invalidProvider
	 */
	public function testInvalidImpersonationLogsOut(?bool $impersonatorEnabled, ?string $policyError, bool $tooLong, bool $parkedOk, string $reason): void {
		$this->util->method('getImpersonatorUid')->willReturn('admin');
		$this->util->method('getTargetUid')->willReturn('alice');
		$this->util->method('getStartTime')->willReturn(1700000000);
		$this->userSession->method('getUser')->willReturn($this->user('alice'));
		$this->userManager->method('get')->willReturn(
			$impersonatorEnabled === null ? null : $this->user('admin', $impersonatorEnabled)
		);
		$this->policy->method('check')->willReturn($policyError);
		$this->policy->method('hasExceededMaxDuration')->with(1700000000)->willReturn($tooLong);
		$this->util->method('touchParkedToken')->willReturn($parkedOk);
		// the end (and its audit event) goes through the one shared place, with the reason
		$this->util->expects($this->once())->method('endImpersonation')->with($reason);
		$this->userSession->expects($this->once())->method('logout');
		$this->assertFalse($this->guard->validate());
	}

	public function testAnImpersonationThatWasEndedOutsideOfItsSessionDoesNotGoOn(): void {
		// its record is the authority: the reconcile job, an administrator or the guard closed it
		$this->util->method('getImpersonatorUid')->willReturn('admin');
		$this->util->method('getTargetUid')->willReturn('alice');
		$this->userSession->method('getUser')->willReturn($this->user('alice'));
		$this->endedElsewhere = true;
		$this->userManager->expects($this->never())->method('get');
		$this->util->expects($this->once())->method('endImpersonation')->with(Util::REASON_ENDED_ELSEWHERE);
		$this->userSession->expects($this->once())->method('logout');
		$this->assertFalse($this->guard->validate());
	}

	public function testAnImpersonatedSessionThatIsNotBoundToItsTokenAnymoreIsEnded(): void {
		$this->util->method('getImpersonatorUid')->willReturn('admin');
		$this->util->method('getTargetUid')->willReturn('alice');
		$this->userSession->method('getUser')->willReturn($this->user('alice'));
		$this->bound = false;
		$this->util->expects($this->once())->method('endImpersonation')->with(Util::REASON_OTHER_SESSION);
		$this->userSession->expects($this->once())->method('logout');
		$this->assertFalse($this->guard->validate());
	}

	public function testSessionWithoutUser(): void {
		$this->util->method('getImpersonatorUid')->willReturn('admin');
		$this->util->method('getTargetUid')->willReturn('alice');
		$this->userSession->method('getUser')->willReturn(null);
		// the observed condition is logged, not a guess at its cause
		$this->logger->expects($this->once())->method('warning')->with(
			$this->anything(),
			$this->callback(function (array $context) {
				return $context['reason'] === 'the session has no user' && $context['target'] === 'alice';
			})
		);
		$this->util->expects($this->once())->method('endImpersonation')->with('the session has no user');
		$this->userSession->expects($this->once())->method('logout');
		$this->assertFalse($this->guard->validate());
	}

	public function testSessionOfAnotherUserThanTheImpersonatedOne(): void {
		$this->util->method('getImpersonatorUid')->willReturn('admin');
		$this->util->method('getTargetUid')->willReturn('alice');
		$this->userSession->method('getUser')->willReturn($this->user('bob'));
		$this->policy->expects($this->never())->method('check');
		$this->util->expects($this->once())->method('endImpersonation')
			->with('the user of the session is not the impersonated user');
		$this->userSession->expects($this->once())->method('logout');
		$this->assertFalse($this->guard->validate());
	}

	public function testCheckDoesNotTouchSessionsThatDoNotImpersonate(): void {
		$this->util->method('isImpersonating')->willReturn(false);
		$this->request('POST', '/settings/personal/authtokens');
		$this->userManager->expects($this->never())->method('get');
		$this->policy->expects($this->never())->method('check');
		// nothing is looked up while no impersonation is recorded
		$this->util->expects($this->never())->method('getSessionSecrets');
		$this->cleanup->expects($this->never())->method('findToken');
		$this->assertSame(ImpersonationGuard::PROCEED, $this->guard->check());
	}

	/**
	 * admin impersonates alice; the request is not part of the impersonated session
	 */
	private function otherRequestWhileAnImpersonationIsActive(array $record = self::RECORD): void {
		$this->util->method('isImpersonating')->willReturn(false);
		$this->registry->method('all')->willReturn(['r1' => $record, 'broken' => null]);
		$this->tokens = [
			'the-impersonated-session-id' => ['id' => 60, 'uid' => 'alice'],
			'own-session-id' => ['id' => 7, 'uid' => 'alice'],
			'own-app-password' => ['id' => 8, 'uid' => 'alice'],
			// a token of somebody else that got the id of the recorded one (a database may reuse ids)
			'reused-id-of-another-user' => ['id' => 60, 'uid' => 'bob'],
			// the same secrets in the shape of a session id (as a request parameter has to be to be looked at)
			self::sessionId('impersonated') => ['id' => 60, 'uid' => 'alice'],
			self::sessionId('reused') => ['id' => 60, 'uid' => 'bob'],
			self::sessionId('own') => ['id' => 7, 'uid' => 'alice'],
		];
		$this->request->method('getRemoteAddress')->willReturn('10.0.0.9');
	}

	public function testRequestsOfOtherSessionsProceedWhileAnImpersonationIsActive(): void {
		$this->otherRequestWhileAnImpersonationIsActive();
		// e.g. the account owner's own browser, or a sync client with its app password
		$this->util->method('getSessionSecrets')->willReturn(['own-session-id']);
		$_SERVER['PHP_AUTH_PW'] = 'own-app-password';
		$this->request->method('getHeader')->with('Authorization')->willReturn('Basic ' . \base64_encode('alice:own-app-password'));
		// request values that are no session id, or the session id of somebody else's token with a reused id
		$this->params = [
			'dir' => '/',
			'file' => 'report-2026-final-version',
			'password' => self::sessionId('reused'),
			'own' => self::sessionId('own'),
			'unknown' => self::sessionId('nobody has this'),
			'fileids' => [15, 16, 17],
		];
		$this->reconciler->expects($this->never())->method('end');
		$this->userSession->expects($this->never())->method('logout');
		$this->assertSame(ImpersonationGuard::PROCEED, $this->guard->check());
	}

	public static function misuseProvider(): array {
		$basic = 'Basic ' . \base64_encode('alice:the-impersonated-session-id');
		return [
			// the platform accepts the id of a session as a token of its user
			'password of HTTP Basic authentication (header)' => [[], null, $basic, null],
			'password of HTTP Basic authentication (PHP)' => [[], 'the-impersonated-session-id', null, null],
			'password with a colon in it is still read after the first colon' => [[], null, 'basic ' . \base64_encode('alice:the-impersonated-session-id'), null],
			'token authorization' => [[], null, 'token the-impersonated-session-id', null],
			'bearer authorization' => [[], null, 'Bearer   the-impersonated-session-id', null],
			'header under the name some web servers use' => [[], null, null, 'token the-impersonated-session-id'],
			// a session that was logged in with it keeps it
			'token a session was logged in with' => [['some-new-session-id', 'the-impersonated-session-id'], null, null, null],
			// the session of the impersonation without its marker
			'the session itself, unmarked' => [['the-impersonated-session-id'], null, null, null],
			// the login form (and whatever else takes a credential as a parameter)
			'password of the login form' => [[], null, null, null, ['user' => 'alice', 'password' => self::sessionId('impersonated')]],
			'a parameter of any name' => [[], null, null, null, ['token' => self::sessionId('impersonated')]],
			'a nested parameter (e.g. of a JSON body)' => [[], null, null, null, ['login' => ['credentials' => ['password' => self::sessionId('impersonated')]]]],
			'behind other values in the shape of a session id' => [[], null, null, null, self::decoys(200) + ['password' => self::sessionId('impersonated')]],
			'with white space around it' => [[], null, null, null, ['password' => ' ' . self::sessionId('impersonated') . "\n"]],
		];
	}

	/**
	 * @dataProvider misuseProvider
	 */
	public function testTheSessionTokenOfAnImpersonationIsNoCredentialOutsideItsSession(array $sessionSecrets, ?string $password, ?string $header, ?string $redirectHeader, array $params = []): void {
		$this->otherRequestWhileAnImpersonationIsActive();
		$this->params = $params;
		$this->util->method('getSessionSecrets')->willReturn($sessionSecrets);
		if ($password !== null) {
			$_SERVER['PHP_AUTH_PW'] = $password;
		}
		if ($redirectHeader !== null) {
			$_SERVER['REDIRECT_HTTP_AUTHORIZATION'] = $redirectHeader;
		}
		$this->request->method('getHeader')->with('Authorization')->willReturn($header);
		$this->request('GET', '/cloud/user/signing-key');
		// the impersonation is ended (its token revoked) and the request refused
		$this->reconciler->expects($this->once())->method('end')->with('r1', self::RECORD, Reconciler::REASON_TOKEN_MISUSE);
		$this->userSession->expects($this->once())->method('logout');
		$this->logger->expects($this->once())->method('warning')->with(
			$this->stringContains('presented by a request that is not part of the impersonated session'),
			$this->callback(function (array $context) {
				return $context['target'] === 'alice' && $context['impersonator'] === 'admin' && $context['remote'] === '10.0.0.9';
			})
		);
		$this->assertSame(ImpersonationGuard::TOKEN_MISUSE, $this->guard->check());
	}

	/**
	 * @return array<string, string> request parameters in the shape of a session id
	 */
	private static function decoys(int $count): array {
		$decoys = [];
		for ($i = 0; $i < $count; $i++) {
			$decoys["d$i"] = self::sessionId("decoy $i");
		}
		return $decoys;
	}

	public function testOnlyRequestValuesInTheShapeOfASessionIdAreLookedUp(): void {
		$this->otherRequestWhileAnImpersonationIsActive();
		$this->util->method('getSessionSecrets')->willReturn([]);
		$this->params = ['a' => 'short', 'b' => \str_repeat('x', 300), 'c' => 'with spaces and so on, definitely no id', 'd' => 42, 'e' => null];
		$this->cleanup->expects($this->never())->method('findToken');
		$this->assertSame(ImpersonationGuard::PROCEED, $this->guard->check());
	}

	public function testASessionIdOfAnotherShapeThanThisPhpMakesIsRecognizedByItsRecordedLength(): void {
		// the session was started by a server with other session settings, or by a session
		// handler with ids of its own: the record says how long its id is
		$foreign = 'Zz_' . \str_repeat('q', 37);
		$this->assertSame(40, \strlen($foreign));
		$this->otherRequestWhileAnImpersonationIsActive(self::RECORD + ['sid' => 40]);
		$this->tokens[$foreign] = ['id' => 60, 'uid' => 'alice'];
		$this->util->method('getSessionSecrets')->willReturn([]);
		$this->params = ['user' => 'alice', 'password' => $foreign];
		$this->reconciler->expects($this->once())->method('end')
			->with('r1', self::RECORD + ['sid' => 40], Reconciler::REASON_TOKEN_MISUSE);
		$this->assertSame(ImpersonationGuard::TOKEN_MISUSE, $this->guard->check());
	}

	public function testWithoutARecordedLengthOnlyTheShapeOfThisPhpCounts(): void {
		$foreign = 'Zz_' . \str_repeat('q', 37);
		$this->otherRequestWhileAnImpersonationIsActive();
		$this->tokens[$foreign] = ['id' => 60, 'uid' => 'alice'];
		$this->util->method('getSessionSecrets')->willReturn([]);
		$this->params = ['user' => 'alice', 'password' => $foreign];
		$this->cleanup->expects($this->never())->method('findToken');
		$this->assertSame(ImpersonationGuard::PROCEED, $this->guard->check());
	}

	public function testARequestWithMoreCandidatesThanARequestNeedsIsRefused(): void {
		// no value may hide behind others, and the lookups are no way to make the server work
		$this->otherRequestWhileAnImpersonationIsActive();
		$this->util->method('getSessionSecrets')->willReturn([]);
		$this->params = self::decoys(300) + ['password' => self::sessionId('impersonated')];
		$this->request('POST', '/login');
		// a refusal, not an error of the app - and nothing an anonymous client can fill the log with
		$this->logger->expects($this->never())->method('logException');
		$this->logger->expects($this->never())->method('warning');
		$this->logger->expects($this->once())->method('info')->with(
			$this->stringContains('Refused'),
			$this->callback(function (array $context) {
				return $context['path'] === '/login' && \strpos($context['reason'], 'too many request values') === 0;
			})
		);
		$this->assertSame(ImpersonationGuard::UNVERIFIED, $this->guard->check());

		// without a recorded impersonation the request is not looked at at all
		$registry = $this->createMock(ActiveImpersonations::class);
		$registry->method('all')->willReturn([]);
		$guard = new ImpersonationGuard($this->util, $this->policy, $this->userSession, $this->userManager, $this->request, $this->logger, $registry, $this->cleanup, $this->reconciler);
		$this->assertSame(ImpersonationGuard::PROCEED, $guard->check());
	}

	public function testATokenWhoseRevocationIsStillPendingIsRefusedAsWell(): void {
		$pending = self::RECORD + ['pending' => true, 'ended' => 1700000100];
		$this->otherRequestWhileAnImpersonationIsActive($pending);
		$this->util->method('getSessionSecrets')->willReturn([]);
		$this->request->method('getHeader')->willReturn('token the-impersonated-session-id');
		$this->reconciler->expects($this->once())->method('end')->with('r1', $pending, Reconciler::REASON_TOKEN_MISUSE);
		$this->assertSame(ImpersonationGuard::TOKEN_MISUSE, $this->guard->check());
	}

	public function testCheckRefusesWhenTheCredentialsCanNotBeLookedUp(): void {
		$this->util->method('isImpersonating')->willReturn(false);
		$this->registry->method('all')->willReturn(['r1' => self::RECORD]);
		$this->util->method('getSessionSecrets')->willReturn(['own-session-id']);
		$cleanup = $this->createMock(CredentialCleanup::class);
		$cleanup->method('findToken')->willThrowException(new \RuntimeException('token backend down'));
		$guard = new ImpersonationGuard($this->util, $this->policy, $this->userSession, $this->userManager, $this->request, $this->logger, $this->registry, $cleanup, $this->reconciler);
		// whether the request rides on the token of the impersonation can not be told
		$this->assertSame(ImpersonationGuard::UNVERIFIED, $guard->check());
	}

	public function testCheckRefusesWhenTheImpersonationCanNotBeEnded(): void {
		$this->otherRequestWhileAnImpersonationIsActive();
		$this->util->method('getSessionSecrets')->willReturn(['the-impersonated-session-id']);
		$this->reconciler->method('end')->willThrowException(new \RuntimeException('database down'));
		$this->assertSame(ImpersonationGuard::UNVERIFIED, $this->guard->check());
	}

	public function testALogoutThatFailsAfterAMisuseStillRefusesTheRequest(): void {
		$this->otherRequestWhileAnImpersonationIsActive();
		$this->util->method('getSessionSecrets')->willReturn(['the-impersonated-session-id']);
		$this->userSession->method('logout')->willThrowException(new \RuntimeException('logout failed'));
		$this->assertSame(ImpersonationGuard::TOKEN_MISUSE, $this->guard->check());
	}

	public function testCheckLetsAValidImpersonationProceed(): void {
		$this->validImpersonation();
		$this->request('GET', '/apps/files/');
		$this->util->expects($this->never())->method('endImpersonation');
		$this->assertSame(ImpersonationGuard::PROCEED, $this->guard->check());
	}

	public function testCheckRefusesAForbiddenRequestWithoutNeedingTheReValidation(): void {
		$this->util->method('isImpersonating')->willReturn(true);
		$this->util->method('getImpersonatorUid')->willReturn('admin');
		$this->policy->method('getExtraForbiddenPrefixes')->willReturn([]);
		$this->request('POST', '/settings/personal/authtokens');
		// a failing backend must not open the deny-list: it is not even asked
		$this->userManager->expects($this->never())->method('get');
		$this->policy->expects($this->never())->method('check');
		$this->logger->expects($this->once())->method('warning');
		$this->assertSame(ImpersonationGuard::FORBIDDEN_REQUEST, $this->guard->check());
	}

	public function testCheckRefusesWhenTheReValidationFails(): void {
		$this->util->method('isImpersonating')->willReturn(true);
		$this->util->method('getImpersonatorUid')->willReturn('admin');
		$this->util->method('getTargetUid')->willReturn('alice');
		$this->policy->method('getExtraForbiddenPrefixes')->willReturn([]);
		$this->userSession->method('getUser')->willReturn($this->user('alice'));
		$this->userManager->method('get')->willThrowException(new \RuntimeException('user backend down'));
		$this->request('GET', '/apps/files/');
		$this->logger->expects($this->once())->method('logException');
		// the request does not continue in the impersonated session without the check
		$this->assertSame(ImpersonationGuard::UNVERIFIED, $this->guard->check());
	}

	public function testCheckRefusesWhenTheReValidationFailsWithAnError(): void {
		$this->util->method('isImpersonating')->willReturn(true);
		$this->util->method('getImpersonatorUid')->willReturn('admin');
		$this->policy->method('getExtraForbiddenPrefixes')->willReturn([]);
		$this->userSession->method('getUser')->willThrowException(new \TypeError('unexpected'));
		$this->request('GET', '/apps/files/');
		$this->assertSame(ImpersonationGuard::UNVERIFIED, $this->guard->check());
	}

	public function testCheckRefusesWhenTheDenyListCanNotBeEvaluated(): void {
		$this->util->method('isImpersonating')->willReturn(true);
		$this->policy->method('getExtraForbiddenPrefixes')->willThrowException(new \RuntimeException('config backend down'));
		$this->request('GET', '/apps/files/');
		$this->assertSame(ImpersonationGuard::UNVERIFIED, $this->guard->check());
	}

	public function testCheckRefusesWhenTheSessionCanNotBeRead(): void {
		// whether the session impersonates is unknown: refuse
		$this->util->method('isImpersonating')->willThrowException(new \RuntimeException('session backend down'));
		$this->request('GET', '/apps/files/');
		$this->assertSame(ImpersonationGuard::UNVERIFIED, $this->guard->check());
	}

	public function testCheckRefusesWhenTheLogoutOfAnEndedImpersonationFails(): void {
		$this->util->method('isImpersonating')->willReturn(true);
		$this->util->method('getImpersonatorUid')->willReturn('admin');
		$this->util->method('getTargetUid')->willReturn('alice');
		$this->policy->method('getExtraForbiddenPrefixes')->willReturn([]);
		$this->userSession->method('getUser')->willReturn($this->user('alice'));
		$this->userManager->method('get')->willReturn(null);
		$this->util->expects($this->once())->method('endImpersonation');
		$this->userSession->method('logout')->willThrowException(new \RuntimeException('logout failed'));
		$this->request('GET', '/apps/files/');
		// the session is still the impersonated user's: the request must not go on
		$this->assertSame(ImpersonationGuard::UNVERIFIED, $this->guard->check());
	}

	public function testCheckProceedsAfterAnImpersonationWasEnded(): void {
		// the request goes on as an anonymous one
		$this->util->method('isImpersonating')->willReturn(true);
		$this->util->method('getImpersonatorUid')->willReturn('admin');
		$this->util->method('getTargetUid')->willReturn('alice');
		$this->policy->method('getExtraForbiddenPrefixes')->willReturn([]);
		$this->userSession->method('getUser')->willReturn($this->user('alice'));
		$this->userManager->method('get')->willReturn(null);
		$this->util->expects($this->once())->method('endImpersonation');
		$this->userSession->expects($this->once())->method('logout');
		$this->request('GET', '/apps/files/');
		$this->assertSame(ImpersonationGuard::PROCEED, $this->guard->check());
	}

	public static function requestProvider(): array {
		return [
			[true, 'POST', '/settings/personal/authtokens', null, true],
			[true, 'POST', '/settings/personal/authtokens/', null, true],
			[true, 'POST', '//settings/personal/authtokens', null, true],
			[true, 'POST', '/settings//personal/authtokens', null, true],
			[true, 'POST', '/settings/personal/authtoken%73', null, true],
			[true, 'POST', '/settings/personal%2Fauthtokens', null, true],
			[true, 'POST', '/settings/personal/authtokens', '//settings/personal/authtokens', true],
			[true, 'GET', '/settings/personal/authtokens', null, false],
			// the login form accepts a session id as a password: no login inside an impersonated session
			[true, 'POST', '/login', null, true],
			[true, 'POST', '/index.php/login', null, true],
			[true, 'POST', '/Login/', null, true],
			[true, 'GET', '/login', null, false],
			[false, 'POST', '/login', null, false],
			[true, 'DELETE', '/settings/personal/authtokens/12', null, false],
			[true, 'GET', '/cloud/user/signing-key', null, true],
			[true, 'POST', '/cloud//user/signing-key/', null, true],
			[true, 'GET', '/cloud/user', null, false],
			[true, 'GET', '/apps/oauth2/authorize', null, true],
			[true, 'POST', '/apps/oauth2', null, true],
			[true, 'POST', '/apps/oauth2settings', null, false],
			[true, 'POST', '/apps/files/ajax/upload.php', null, false],
			[false, 'POST', '/settings/personal/authtokens', null, false],
			[false, 'GET', '/cloud/user/signing-key', null, false],
			// the comparison is wider than the router: letter case ...
			[true, 'POST', '/Settings/Personal/AuthTokens', null, true],
			[true, 'post', '/settings/personal/authtokens', null, true],
			[true, 'GET', '/Cloud/User/Signing-Key', null, true],
			[true, 'GET', '/apps/OAuth2/authorize', null, true],
			// ... and other entry points
			[true, 'GET', '/ocs/cloud/user/signing-key', null, true],
			[true, 'GET', '/ocs/v1.php/cloud/user/signing-key', null, true],
			[true, 'GET', '/ocs/v2.php/cloud/user/signing-key', null, true],
			[true, 'POST', '/index.php/settings/personal/authtokens', null, true],
			[true, 'GET', '/index.php/apps/oauth2/authorize', null, true],
			[true, 'GET', '/ocs/v1.php/cloud/user', null, false],
			[true, 'GET', '/ocs', null, false],
			// no path info: the front page
			[true, 'GET', '', null, false],
			[true, 'GET', '/', null, false],
			// the way back is never refused
			[true, 'GET', '/logout', null, false],
		];
	}

	/**
	 * @dataProvider requestProvider
	 */
	public function testIsForbiddenRequest(bool $impersonating, string $method, string $raw, ?string $decoded, bool $forbidden): void {
		$this->util->method('isImpersonating')->willReturn($impersonating);
		$this->policy->method('getExtraForbiddenPrefixes')->willReturn([]);
		$this->request->method('getMethod')->willReturn($method);
		$this->request->method('getRawPathInfo')->willReturn($raw);
		$this->request->method('getPathInfo')->willReturn($decoded ?? \rawurldecode($raw));
		$this->assertSame($forbidden, $this->guard->isForbiddenRequest());
	}

	public static function operatorPrefixProvider(): array {
		return [
			['GET', '/apps/customtokens/create', true],
			['POST', '/apps/customtokens', true],
			['GET', '/apps/CustomTokens/x', true],
			['GET', '/index.php/apps/customtokens/x', true],
			['GET', '/apps/customtokensettings', false],
			['GET', '/apps/files/', false],
			// a prefix can not lock the impersonator in
			['GET', '/logout', false],
		];
	}

	/**
	 * @dataProvider operatorPrefixProvider
	 */
	public function testPrefixesAddedByTheOperatorAreForbidden(string $method, string $path, bool $forbidden): void {
		$this->util->method('isImpersonating')->willReturn(true);
		$this->policy->method('getExtraForbiddenPrefixes')->willReturn(['/apps/customtokens/', '/logout/']);
		$this->request($method, $path);
		$this->assertSame($forbidden, $this->guard->isForbiddenRequest());
	}

	public function testARequestWhosePathCanNotBeDeterminedIsForbiddenWhileImpersonating(): void {
		$this->util->method('isImpersonating')->willReturn(true);
		$this->policy->method('getExtraForbiddenPrefixes')->willReturn([]);
		$this->request->method('getMethod')->willReturn('GET');
		$this->request->method('getRawPathInfo')->willThrowException(new \Exception('The requested uri cannot be processed'));
		$this->request->method('getPathInfo')->willThrowException(new \Exception('The requested uri cannot be processed'));
		$this->assertTrue($this->guard->isForbiddenRequest());
		$this->assertSame('', ImpersonationGuard::normalizedPath($this->request));
	}

	public function testARequestWhosePathCanNotBeDeterminedIsNoConcernWithoutImpersonation(): void {
		$this->util->method('isImpersonating')->willReturn(false);
		$this->request->method('getRawPathInfo')->willThrowException(new \Exception('The requested uri cannot be processed'));
		$this->assertFalse($this->guard->isForbiddenRequest());
		$this->assertSame(ImpersonationGuard::PROCEED, $this->guard->check());
	}

	public function testNormalizedPath(): void {
		$this->request->method('getRawPathInfo')->willReturn('//logout/');
		$this->request->method('getPathInfo')->willReturn('//logout/');
		$this->assertSame('/logout', ImpersonationGuard::normalizedPath($this->request));
	}
}
