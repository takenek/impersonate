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
use OCP\IConfig;
use OCP\ILogger;
use OCP\IRequest;
use OCP\ISession;
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
		$_GET = [];
		$_POST = [];
		\OC_User::setIncognitoMode(false);
		parent::tearDown();
	}

	protected function setUp(): void {
		parent::setUp();
		$this->serverBackup = $_SERVER;
		unset(
			$_SERVER['PHP_AUTH_PW'],
			$_SERVER['PHP_AUTH_USER'],
			$_SERVER['REDIRECT_HTTP_AUTHORIZATION'],
			$_SERVER['CONTENT_TYPE'],
			$_SERVER['HTTP_CONTENT_TYPE']
		);
		// the entry point of the request: the front controller unless a test says otherwise
		$_SERVER['SCRIPT_FILENAME'] = '/var/www/owncloud/index.php';
		$_GET = [];
		$_POST = [];
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

	/**
	 * The content type of a request can come from three places: $_SERVER['CONTENT_TYPE'],
	 * $_SERVER['HTTP_CONTENT_TYPE'] (the name some web servers use) and the platform's view of the header.
	 */
	private function contentType(?string $contentType, ?string $httpContentType, ?string $platformHeader): void {
		if ($contentType !== null) {
			$_SERVER['CONTENT_TYPE'] = $contentType;
		}
		if ($httpContentType !== null) {
			$_SERVER['HTTP_CONTENT_TYPE'] = $httpContentType;
		}
		$this->request->method('getHeader')->willReturnCallback(function ($name) use ($platformHeader) {
			return $name === 'Content-Type' ? $platformHeader : null;
		});
	}

	public static function rawPutBodyProvider(): array {
		return [
			'a file' => ['application/octet-stream', null, null],
			'a text file' => ['text/plain; charset=utf-8', null, null],
			'a WebDAV document' => ['text/xml', null, null],
			'no content type at all' => [null, null, null],
			'an empty content type' => ['', null, null],
			'the same type under every name' => ['image/png', 'image/png', 'image/png'],
		];
	}

	/**
	 * The check runs for the requests of everybody while somebody impersonates somebody else. The
	 * platform hands the body of such a PUT request out once: if the guard asked for the parameters,
	 * an upload through a public link was refused and other requests were handled differently.
	 *
	 * @dataProvider rawPutBodyProvider
	 */
	public function testThePlatformIsNotAskedForTheParametersOfAPutRequestWhoseBodyHoldsNone(?string $contentType, ?string $httpContentType, ?string $platformHeader): void {
		$this->otherRequestWhileAnImpersonationIsActive();
		$this->util->method('getSessionSecrets')->willReturn([]);
		$this->contentType($contentType, $httpContentType, $platformHeader);
		$this->request('PUT', '/apps/files/upload');
		$this->request->expects($this->never())->method('getParams');
		$this->reconciler->expects($this->never())->method('end');
		$this->logger->expects($this->never())->method('logException');
		$this->assertSame(ImpersonationGuard::PROCEED, $this->guard->check());
	}

	public function testTheQueryOfSuchAPutRequestIsStillExamined(): void {
		$this->otherRequestWhileAnImpersonationIsActive();
		$this->util->method('getSessionSecrets')->willReturn([]);
		$_SERVER['CONTENT_TYPE'] = 'application/octet-stream';
		$_GET = ['dir' => '/', 'token' => self::sessionId('impersonated')];
		$this->request('PUT', '/apps/files/upload');
		$this->request->expects($this->never())->method('getParams');
		$this->reconciler->expects($this->once())->method('end')->with('r1', self::RECORD, Reconciler::REASON_TOKEN_MISUSE);
		$this->assertSame(ImpersonationGuard::TOKEN_MISUSE, $this->guard->check());
	}

	public static function parameterBodyProvider(): array {
		return [
			'PUT with a JSON body' => ['PUT', 'application/json', null, null],
			'PUT with a JSON body and a charset' => ['PUT', 'application/json; charset=utf-8', null, null],
			'PUT, the type in another letter case' => ['PUT', 'Application/JSON', null, null],
			'PUT with a form encoded body' => ['PUT', 'application/x-www-form-urlencoded', null, null],
			// one place that names JSON or a form is enough: the body is only left alone if none does
			'PUT, the type only under the name some web servers use' => ['PUT', null, 'application/json', null],
			'PUT, an empty type and the real one under the other name' => ['PUT', '', 'application/json', null],
			'PUT, two names that disagree' => ['PUT', 'text/plain', 'application/x-www-form-urlencoded', null],
			'PUT, only the platform knows the type' => ['PUT', null, null, 'application/json'],
			'PUT, the platform disagrees with the web server' => ['PUT', 'application/octet-stream', null, 'application/json; charset=utf-8'],
			// only PUT bodies are handed out as a stream: everything else is as it was
			'POST with a JSON body (the login form takes one)' => ['POST', 'application/json', null, null],
			'POST with any other body' => ['POST', 'application/octet-stream', null, null],
			'PATCH with any other body' => ['PATCH', 'text/plain', null, null],
			'DELETE without a body' => ['DELETE', null, null, null],
		];
	}

	/**
	 * @dataProvider parameterBodyProvider
	 */
	public function testABodyThatHoldsParametersIsExamined(string $method, ?string $contentType, ?string $httpContentType, ?string $platformHeader): void {
		$this->otherRequestWhileAnImpersonationIsActive();
		$this->util->method('getSessionSecrets')->willReturn([]);
		$this->contentType($contentType, $httpContentType, $platformHeader);
		$this->params = ['user' => 'alice', 'password' => self::sessionId('impersonated')];
		$this->request($method, '/login');
		$this->reconciler->expects($this->once())->method('end')->with('r1', self::RECORD, Reconciler::REASON_TOKEN_MISUSE);
		$this->assertSame(ImpersonationGuard::TOKEN_MISUSE, $this->guard->check());
	}

	public static function webDavEntryPointProvider(): array {
		return [
			'WebDAV' => ['/var/www/owncloud/remote.php', 'PUT', 'application/json'],
			'WebDAV of public links' => ['/var/www/owncloud/public.php', 'PUT', 'application/json'],
			'a WebDAV document' => ['/var/www/owncloud/remote.php', 'PROPFIND', 'application/xml'],
			'a form encoded body' => ['/var/www/owncloud/remote.php', 'POST', 'application/x-www-form-urlencoded'],
			'on a file system that ignores the letter case' => ['C:\\inetpub\\owncloud/Remote.PHP', 'PUT', 'application/json'],
		];
	}

	/**
	 * The body of a WebDAV request is a file or a WebDAV document of any size: decoding a large
	 * JSON file took more memory than the request may use, for every user of the instance.
	 *
	 * @dataProvider webDavEntryPointProvider
	 */
	public function testTheBodyOfAWebDavRequestIsNotDecoded(string $script, string $method, string $contentType): void {
		$this->otherRequestWhileAnImpersonationIsActive();
		$this->util->method('getSessionSecrets')->willReturn(['own-session-id']);
		$_SERVER['SCRIPT_FILENAME'] = $script;
		$_SERVER['CONTENT_TYPE'] = $contentType;
		// what the body would decode to
		$this->params = ['password' => self::sessionId('impersonated')];
		$this->request($method, '/webdav/report.json');
		$this->request->expects($this->never())->method('getParams');
		$this->reconciler->expects($this->never())->method('end');
		$this->assertSame(ImpersonationGuard::PROCEED, $this->guard->check());
	}

	public static function webDavCredentialProvider(): array {
		return [
			'the password of HTTP Basic authentication' => ['Basic ' . \base64_encode('alice:the-impersonated-session-id'), [], [], []],
			'a token' => ['Bearer the-impersonated-session-id', [], [], []],
			'the session of the request' => [null, ['the-impersonated-session-id'], [], []],
			'a parameter of the query' => [null, [], ['access_token' => self::sessionId('impersonated')], []],
			'a parameter of a form' => [null, [], [], ['login' => ['password' => self::sessionId('impersonated')]]],
		];
	}

	/**
	 * @dataProvider webDavCredentialProvider
	 */
	public function testWhereAWebDavRequestCarriesCredentialsIsStillExamined(?string $header, array $sessionSecrets, array $query, array $form): void {
		$this->otherRequestWhileAnImpersonationIsActive();
		$this->util->method('getSessionSecrets')->willReturn($sessionSecrets);
		$_SERVER['SCRIPT_FILENAME'] = '/var/www/owncloud/remote.php';
		$_SERVER['CONTENT_TYPE'] = 'application/octet-stream';
		$_GET = $query;
		$_POST = $form;
		$this->request->method('getHeader')->with('Authorization')->willReturn($header);
		$this->request('PUT', '/webdav/file.bin');
		$this->request->expects($this->never())->method('getParams');
		$this->reconciler->expects($this->once())->method('end')->with('r1', self::RECORD, Reconciler::REASON_TOKEN_MISUSE);
		$this->assertSame(ImpersonationGuard::TOKEN_MISUSE, $this->guard->check());
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

	public function testARequestWhoseImpersonationWasEndedByTheCheckIsRefused(): void {
		// What the rest of the request would do must not depend on how the platform reads the
		// identity after the logout (web interface, OCS, WebDAV): it is refused.
		$this->util->method('isImpersonating')->willReturn(true);
		$this->util->method('getImpersonatorUid')->willReturn('admin');
		$this->util->method('getTargetUid')->willReturn('alice');
		$this->policy->method('getExtraForbiddenPrefixes')->willReturn([]);
		$this->userSession->method('getUser')->willReturn($this->user('alice'));
		$this->userManager->method('get')->willReturn(null);
		$this->util->expects($this->once())->method('endImpersonation');
		$this->userSession->expects($this->once())->method('logout');
		$this->request('GET', '/apps/files/');
		$this->assertSame(ImpersonationGuard::ENDED, $this->guard->check());
	}

	public function testTheLogoutGoesOnAfterItsImpersonationWasEndedByTheCheck(): void {
		$this->util->method('isImpersonating')->willReturn(true);
		$this->util->method('getImpersonatorUid')->willReturn('admin');
		$this->util->method('getTargetUid')->willReturn('alice');
		$this->policy->method('getExtraForbiddenPrefixes')->willReturn([]);
		$this->userSession->method('getUser')->willReturn($this->user('alice'));
		$this->userManager->method('get')->willReturn(null);
		$this->util->expects($this->once())->method('endImpersonation');
		$this->request('GET', '//logout/');
		$this->assertSame(ImpersonationGuard::PROCEED, $this->guard->check());
	}

	public static function incognitoProvider(): array {
		return [
			'ended elsewhere' => [true, true, false, Util::REASON_ENDED_ELSEWHERE],
			'not bound to its token' => [false, false, false, Util::REASON_OTHER_SESSION],
			'maximum duration reached' => [false, true, true, 'the maximum duration of the impersonation was reached'],
			'nothing to decide without the users' => [false, true, false, null],
		];
	}

	/**
	 * Core hides the user of the session (e.g. an update is pending): what needs no user is still
	 * decided.
	 *
	 * @dataProvider incognitoProvider
	 */
	public function testInIncognitoModeWhatNeedsNoUserIsStillChecked(bool $endedElsewhere, bool $bound, bool $tooLong, ?string $reason): void {
		\OC_User::setIncognitoMode(true);
		$this->util->method('getImpersonatorUid')->willReturn('admin');
		$this->util->method('getTargetUid')->willReturn('alice');
		$this->util->method('getStartTime')->willReturn(1700000000);
		$this->endedElsewhere = $endedElsewhere;
		$this->bound = $bound;
		$this->policy->method('hasExceededMaxDuration')->with(1700000000)->willReturn($tooLong);
		// the users are not asked
		$this->userSession->expects($this->never())->method('getUser');
		$this->userManager->expects($this->never())->method('get');
		if ($reason === null) {
			$this->util->expects($this->never())->method('endImpersonation');
			$this->assertTrue($this->guard->validate());
		} else {
			$this->util->expects($this->once())->method('endImpersonation')->with($reason);
			$this->userSession->expects($this->once())->method('logout');
			$this->assertFalse($this->guard->validate());
		}
	}

	/**
	 * @return ISession|MockObject
	 */
	private function sessionOf(?string $impersonator) {
		$session = $this->createMock(ISession::class);
		$session->method('get')->willReturnCallback(function ($key) use ($impersonator) {
			return $key === Util::SESSION_IMPERSONATOR ? $impersonator : null;
		});
		return $session;
	}

	/**
	 * @param array<string, string> $values app values of the app
	 * @return IConfig|MockObject
	 */
	private function configWith(array $values) {
		$config = $this->createMock(IConfig::class);
		$config->method('getAppKeys')->willReturn(\array_keys($values));
		$config->method('getAppValue')->willReturnCallback(function ($app, $key, $default = '') use ($values) {
			return $values[$key] ?? $default;
		});
		return $config;
	}

	public static function withoutGuardProvider(): array {
		$record = \json_encode(self::RECORD);
		return [
			'nothing recorded' => [null, ['enabled' => 'yes'], ImpersonationGuard::PROCEED],
			'the session impersonates' => ['admin', [], ImpersonationGuard::UNVERIFIED],
			'an impersonation is recorded' => [null, ['active_aaaaaaaaaaaaaaaa' => $record], ImpersonationGuard::UNVERIFIED],
			'its token may still be valid' => [null, ['active_aaaaaaaaaaaaaaaa' => \json_encode(self::RECORD + ['pending' => true, 'ended' => 1700000100])], ImpersonationGuard::UNVERIFIED],
			// what names no credential refuses nothing
			'its token is known to be revoked' => [null, ['active_aaaaaaaaaaaaaaaa' => \json_encode(self::RECORD + ['pending' => true, 'ended' => 1700000100, 'tokenRevoked' => true])], ImpersonationGuard::PROCEED],
			'an unreadable record' => [null, ['active_aaaaaaaaaaaaaaaa' => 'garbage'], ImpersonationGuard::PROCEED],
			'another value of the app' => [null, ['starts_blocked' => 'true', 'activeX' => $record], ImpersonationGuard::PROCEED],
		];
	}

	/**
	 * The guard could not be built (e.g. a service of the app throws after a platform update).
	 *
	 * @dataProvider withoutGuardProvider
	 */
	public function testWithoutTheGuardARequestIsRefusedWhenAnImpersonationCouldBeInvolved(?string $impersonator, array $values, int $expected): void {
		$this->assertSame($expected, ImpersonationGuard::statusWithoutGuard($this->sessionOf($impersonator), $this->configWith($values)));
	}

	public function testWithoutTheGuardWhatCanNotBeToldIsRefused(): void {
		$this->assertSame(ImpersonationGuard::UNVERIFIED, ImpersonationGuard::statusWithoutGuard(null, $this->configWith([])), 'no session');
		$this->assertSame(ImpersonationGuard::UNVERIFIED, ImpersonationGuard::statusWithoutGuard($this->sessionOf(null), null), 'no config');
		$session = $this->createMock(ISession::class);
		$session->method('get')->willThrowException(new \RuntimeException('session backend down'));
		$this->assertSame(ImpersonationGuard::UNVERIFIED, ImpersonationGuard::statusWithoutGuard($session, $this->configWith([])), 'unreadable session');
		$config = $this->createMock(IConfig::class);
		$config->method('getAppKeys')->willThrowException(new \RuntimeException('database down'));
		$this->assertSame(ImpersonationGuard::UNVERIFIED, ImpersonationGuard::statusWithoutGuard($this->sessionOf(null), $config), 'unreadable records');
	}

	public function testTheCommandLineIsNoRequestToCheck(): void {
		// occ and cron.php: onLoadedApps() leaves them alone, also when the guard can not be built
		// (occ app:disable must stay possible); the PHP web server is no command line
		$this->assertTrue(ImpersonationGuard::isCommandLine(), 'the unit tests run on the command line');
		$this->assertFalse($this->guard->isActiveForThisRequest(), 'the guard did not run for this process');
	}

	public function testDiscardingTheOutputBuffersEndsAtABufferThatCanNotBeRemoved(): void {
		// three buffers, the second one can not be removed (ob_end_clean() fails, the level stays)
		$level = 3;
		$attempts = 0;
		ImpersonationGuard::discardOutputBuffers(function () use (&$level): int {
			return $level;
		}, function () use (&$level, &$attempts): bool {
			$attempts++;
			if ($level === 2) {
				return false;
			}
			$level--;
			return true;
		});
		$this->assertSame(2, $level);
		$this->assertSame(2, $attempts);

		// a removal that reports success but leaves the level as it was does not loop either
		$attempts = 0;
		ImpersonationGuard::discardOutputBuffers(function (): int {
			return 1;
		}, function () use (&$attempts): bool {
			$attempts++;
			return true;
		});
		$this->assertSame(1, $attempts);

		// removable buffers are all removed
		$level = 4;
		ImpersonationGuard::discardOutputBuffers(function () use (&$level): int {
			return $level;
		}, function () use (&$level): bool {
			$level--;
			return true;
		});
		$this->assertSame(0, $level);
	}

	public function testTheSessionOfOneImpersonationMustNotPresentTheTokenOfAnother(): void {
		// admin impersonates alice in this session (record "own"); the request presents the session id
		// of another impersonation (record "r1") as a token
		$this->validImpersonation();
		$this->request('GET', '/apps/files/');
		$this->util->method('getRecordId')->willReturn('own');
		$this->registry->method('all')->willReturn(['own' => ['token' => 70] + self::RECORD, 'r1' => self::RECORD]);
		$this->tokens = [
			'this-session-id' => ['id' => 70, 'uid' => 'alice'],
			'the-impersonated-session-id' => ['id' => 60, 'uid' => 'alice'],
		];
		$this->util->method('getSessionSecrets')->willReturn(['this-session-id']);
		$this->request->method('getHeader')->willReturnCallback(function ($name) {
			return $name === 'Authorization' ? 'token the-impersonated-session-id' : null;
		});
		$this->reconciler->expects($this->once())->method('end')->with('r1', self::RECORD, Reconciler::REASON_TOKEN_MISUSE);
		$this->userSession->expects($this->once())->method('logout');
		$this->assertSame(ImpersonationGuard::TOKEN_MISUSE, $this->guard->check());
	}

	public function testTheOwnSessionTokenOfAnImpersonatedSessionIsNoMisuse(): void {
		$this->validImpersonation();
		$this->request('GET', '/apps/files/');
		$this->util->method('getRecordId')->willReturn('own');
		$this->registry->method('all')->willReturn(['own' => ['token' => 70] + self::RECORD]);
		$this->tokens = ['this-session-id' => ['id' => 70, 'uid' => 'alice']];
		$this->util->method('getSessionSecrets')->willReturn(['this-session-id']);
		$this->reconciler->expects($this->never())->method('end');
		// nothing else is recorded: nothing is looked up
		$this->cleanup->expects($this->never())->method('findToken');
		$this->assertSame(ImpersonationGuard::PROCEED, $this->guard->check());
	}

	public function testARecordWhoseTokenIsKnownToBeRevokedIsNotWatched(): void {
		// it only waits for its cleanup: its token can not be presented anymore, nothing is looked up
		$this->otherRequestWhileAnImpersonationIsActive(self::RECORD + ['pending' => true, 'ended' => 1700000100, 'tokenRevoked' => true]);
		$this->util->method('getSessionSecrets')->willReturn(['the-impersonated-session-id']);
		$this->params = self::decoys(300);
		$this->cleanup->expects($this->never())->method('findToken');
		$this->assertSame(ImpersonationGuard::PROCEED, $this->guard->check());
	}

	public function testTheLimitOfLookedUpValuesIsExact(): void {
		$this->otherRequestWhileAnImpersonationIsActive();
		$this->util->method('getSessionSecrets')->willReturn([]);
		$this->params = self::decoys(256);
		$this->assertSame(ImpersonationGuard::PROCEED, $this->guard->check(), '256 values are looked up');
		$this->params = self::decoys(257);
		$this->assertSame(ImpersonationGuard::UNVERIFIED, $this->guard->check(), 'one more is refused');
	}

	public function testARequestWithAHugeNumberOfValuesIsRefusedWithoutWalkingThemAll(): void {
		// the walk stops at the limit: what comes after it is not looked at
		$this->otherRequestWhileAnImpersonationIsActive();
		$this->util->method('getSessionSecrets')->willReturn([]);
		$this->params = ['first' => self::decoys(300), 'rest' => \array_fill(0, 200000, self::sessionId('more'))];
		$this->cleanup->expects($this->never())->method('findToken');
		$start = \microtime(true);
		$this->assertSame(ImpersonationGuard::UNVERIFIED, $this->guard->check());
		$this->assertLessThan(5.0, \microtime(true) - $start);
	}

	public function testABasicHeaderIsAlsoDecodedTheTolerantWay(): void {
		// a component that decodes Base64 tolerantly (skipping characters that are no Base64) reads
		// the session id where a strict decoder reads nothing
		$this->otherRequestWhileAnImpersonationIsActive();
		$this->util->method('getSessionSecrets')->willReturn([]);
		$encoded = \base64_encode('alice:the-impersonated-session-id');
		$this->assertFalse(\base64_decode(\substr($encoded, 0, 8) . '*' . \substr($encoded, 8), true));
		$this->request->method('getHeader')->willReturnCallback(function ($name) use ($encoded) {
			return $name === 'Authorization' ? 'Basic ' . \substr($encoded, 0, 8) . '*' . \substr($encoded, 8) : null;
		});
		$this->reconciler->expects($this->once())->method('end')->with('r1', self::RECORD, Reconciler::REASON_TOKEN_MISUSE);
		$this->assertSame(ImpersonationGuard::TOKEN_MISUSE, $this->guard->check());
	}

	public function testThePathIsLoggedWithoutLineBreaks(): void {
		// a refused request may come from anybody: its path does not forge log lines
		$this->util->method('isImpersonating')->willReturn(true);
		$this->util->method('getImpersonatorUid')->willReturn('admin');
		$this->util->method('getTargetUid')->willReturn('alice');
		$this->policy->method('getExtraForbiddenPrefixes')->willReturn([]);
		$this->request('GET', '/apps/oauth2/x%0A2026-11-28 forged%E2%80%A8line%0D');
		$this->logger->expects($this->once())->method('warning')->with(
			$this->anything(),
			$this->callback(function (array $context) {
				return $context['path'] === '/apps/oauth2/x?2026-11-28 forged?line?';
			})
		);
		$this->assertSame(ImpersonationGuard::FORBIDDEN_REQUEST, $this->guard->check());
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
			// "." and ".." are resolved as well: the compared form does not depend on who resolves them
			[true, 'POST', '/settings/personal/./authtokens', null, true],
			[true, 'POST', '/settings/personal/x/../authtokens', null, true],
			[true, 'GET', '/apps/files/../oauth2/authorize', null, true],
			[true, 'GET', '/cloud/user/signing-key/..', null, false],
			[true, 'GET', '/apps/../logout', null, false],
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
