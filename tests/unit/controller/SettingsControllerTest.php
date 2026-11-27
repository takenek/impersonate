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

namespace OCA\Impersonate\Tests\Unit\Controller;

use OCA\Impersonate\AuditTrail;
use OCA\Impersonate\Controller\SettingsController;
use OCA\Impersonate\Policy;
use OCA\Impersonate\RefusedException;
use OCA\Impersonate\Util;
use OCP\AppFramework\Http;
use OCP\IConfig;
use OCP\IL10N;
use OCP\ILogger;
use OCP\IRequest;
use OCP\IUser;
use OCP\IUserManager;
use OCP\IUserSession;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

class SettingsControllerTest extends TestCase {
	/** @var IUserManager|MockObject */
	private $userManager;
	/** @var IUserSession|MockObject */
	private $userSession;
	/** @var IConfig|MockObject */
	private $config;
	/** @var Policy|MockObject */
	private $policy;
	/** @var Util|MockObject */
	private $util;
	/** @var AuditTrail|MockObject */
	private $auditTrail;
	/** @var ILogger|MockObject */
	private $logger;
	/** @var IRequest|MockObject */
	private $request;
	/** @var string|null Authorization header of the request */
	private $authorization;
	/** @var array */
	private $serverBackup;
	/** @var SettingsController */
	private $controller;
	/** @var string */
	private $appEnabled = 'yes';

	protected function tearDown(): void {
		$_SERVER = $this->serverBackup;
		parent::tearDown();
	}

	protected function setUp(): void {
		parent::setUp();
		$this->serverBackup = $_SERVER;
		unset($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'], $_SERVER['REDIRECT_HTTP_AUTHORIZATION']);
		$this->userManager = $this->createMock(IUserManager::class);
		$this->userSession = $this->createMock(IUserSession::class);
		$this->config = $this->createMock(IConfig::class);
		$this->config->method('getAppValue')->willReturnCallback(function ($app, $key, $default = '') {
			return $key === 'enabled' ? $this->appEnabled : $default;
		});
		$l10n = $this->createMock(IL10N::class);
		$l10n->method('t')->willReturnArgument(0);
		$this->policy = $this->createMock(Policy::class);
		$this->util = $this->createMock(Util::class);
		$this->auditTrail = $this->createMock(AuditTrail::class);
		$this->logger = $this->createMock(ILogger::class);
		$this->request = $this->createMock(IRequest::class);
		$this->request->method('getRemoteAddress')->willReturn('10.0.0.1');
		$this->request->method('getHeader')->willReturnCallback(function ($name) {
			return $name === 'Authorization' ? $this->authorization : null;
		});
		$this->controller = new SettingsController(
			'impersonate',
			$this->request,
			$this->userManager,
			$this->userSession,
			$this->logger,
			$this->config,
			$l10n,
			$this->policy,
			$this->util,
			$this->auditTrail
		);
	}

	/**
	 * @return IUser|MockObject
	 */
	private function user(string $uid, int $lastLogin = 1700000000) {
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn($uid);
		$user->method('getLastLogin')->willReturn($lastLogin);
		$user->method('isEnabled')->willReturn(true);
		return $user;
	}

	private function loggedIn(?IUser $user): void {
		$this->userSession->method('getUser')->willReturn($user);
	}

	private function assertError(string $code, $response): void {
		$this->assertSame(Http::STATUS_NOT_FOUND, $response->getStatus());
		$this->assertSame($code, $response->getData()['error']);
	}

	public function testDataForAnonymous(): void {
		$this->loggedIn(null);
		$this->assertSame(['[]', 'false', 'false', false, false, '[]'], $this->controller->getDataForImpersonateApp()->getData());
	}

	public function testDataForAdmin(): void {
		$this->loggedIn($this->user('admin'));
		$this->policy->method('isAdmin')->willReturn(true);
		$this->policy->method('getIncludedGroups')->willReturn(['g1', 'g2']);
		$this->policy->method('isIncludeGroupsMode')->willReturn(true);
		$this->policy->method('isAllGroupAdminsMode')->willReturn(false);
		$this->assertSame(['["g1","g2"]', 'true', 'false', true, false, '[]'], $this->controller->getDataForImpersonateApp()->getData());
	}

	public function testDataForGroupAdminOnlyContainsOwnGroups(): void {
		$carol = $this->user('carol');
		$this->loggedIn($carol);
		$this->policy->method('isAdmin')->willReturn(false);
		$this->policy->method('isDelegatedGroupAdmin')->willReturn(true);
		$this->policy->method('getImpersonableGroupIds')->with($carol)->willReturn(['g1']);
		$this->policy->method('getAdminUidsInGroups')->with(['g1'])->willReturn(['dave']);
		$this->policy->method('getGroupAdminUidsInGroups')->with(['g1'])->willReturn([]);
		$this->policy->method('isIncludeGroupsMode')->willReturn(true);
		$this->policy->method('isAllGroupAdminsMode')->willReturn(false);
		$this->assertSame(['["g1"]', 'true', 'false', false, true, '["dave"]'], $this->controller->getDataForImpersonateApp()->getData());
	}

	public function testDataForGroupAdminNamesTheMembersThatCanNotBeImpersonated(): void {
		$carol = $this->user('carol');
		$this->loggedIn($carol);
		$this->policy->method('isAdmin')->willReturn(false);
		$this->policy->method('isDelegatedGroupAdmin')->willReturn(true);
		$this->policy->method('getImpersonableGroupIds')->willReturn(['g1']);
		$this->policy->method('getAdminUidsInGroups')->willReturn(['dave', 'erin']);
		// group admins in the groups: erin (also an administrator), frank and carol herself
		$this->policy->method('getGroupAdminUidsInGroups')->willReturn(['erin', 'frank', 'carol']);
		$this->policy->method('isIncludeGroupsMode')->willReturn(false);
		$this->policy->method('isAllGroupAdminsMode')->willReturn(true);
		$data = $this->controller->getDataForImpersonateApp()->getData();
		$this->assertSame('["dave","erin","frank"]', $data[5]);
	}

	public function testDataForNormalUserRevealsNothing(): void {
		$this->loggedIn($this->user('bob'));
		$this->policy->method('isAdmin')->willReturn(false);
		$this->policy->method('isDelegatedGroupAdmin')->willReturn(false);
		$this->policy->expects($this->never())->method('getIncludedGroups');
		$this->assertSame(['[]', 'false', 'false', false, false, '[]'], $this->controller->getDataForImpersonateApp()->getData());
	}

	public function testDataWhileImpersonating(): void {
		$this->loggedIn($this->user('alice'));
		$this->util->method('isImpersonating')->willReturn(true);
		$this->assertSame(['[]', 'false', 'false', false, false, '[]'], $this->controller->getDataForImpersonateApp()->getData());
	}

	public function testAppDisabled(): void {
		$this->appEnabled = 'no';
		$this->util->expects($this->never())->method('startImpersonation');
		$this->assertError('cannotImpersonate', $this->controller->impersonate('alice'));
	}

	public function testNoCurrentUser(): void {
		$this->loggedIn(null);
		$this->assertError('cannotImpersonate', $this->controller->impersonate('alice'));
	}

	public function testNestedImpersonation(): void {
		$this->loggedIn($this->user('alice'));
		$this->util->method('isImpersonating')->willReturn(true);
		$this->util->expects($this->never())->method('startImpersonation');
		$this->assertError('stopNestedImpersonation', $this->controller->impersonate('bob'));
	}

	public function testUserWithoutPermissionLearnsNothingAboutTheTarget(): void {
		$this->loggedIn($this->user('bob'));
		$this->policy->method('mayImpersonateAnyone')->willReturn(false);
		$this->userManager->expects($this->never())->method('get');
		$this->assertError('cannotImpersonate', $this->controller->impersonate('admin'));
	}

	public function testUnknownTargetForAdmin(): void {
		$this->loggedIn($this->user('admin'));
		$this->policy->method('mayImpersonateAnyone')->willReturn(true);
		$this->policy->method('isAdmin')->willReturn(true);
		$this->userManager->method('get')->willReturn(null);
		$this->assertError('userNotFound', $this->controller->impersonate('nobody'));
	}

	public function testUnknownTargetForGroupAdmin(): void {
		$this->loggedIn($this->user('carol'));
		$this->policy->method('mayImpersonateAnyone')->willReturn(true);
		$this->policy->method('isAdmin')->willReturn(false);
		$this->userManager->method('get')->willReturn(null);
		$this->assertError('cannotImpersonate', $this->controller->impersonate('nobody'));
	}

	public static function deniedProvider(): array {
		return [
			[true, Policy::ERROR_DISABLED_TARGET, 'userDisabled'],
			[true, Policy::ERROR_CANNOT_IMPERSONATE, 'cannotImpersonate'],
			[false, Policy::ERROR_DISABLED_TARGET, 'cannotImpersonate'],
			[false, Policy::ERROR_ADMIN_TARGET, 'cannotImpersonate'],
			[false, Policy::ERROR_CANNOT_IMPERSONATE, 'cannotImpersonate'],
		];
	}

	/**
	 * @dataProvider deniedProvider
	 */
	public function testDeniedByPolicy(bool $isAdmin, string $policyError, string $expected): void {
		$this->loggedIn($this->user('someone'));
		$this->policy->method('mayImpersonateAnyone')->willReturn(true);
		$this->policy->method('isAdmin')->willReturn($isAdmin);
		$this->userManager->method('get')->willReturn($this->user('alice'));
		$this->policy->method('check')->willReturn($policyError);
		$this->util->expects($this->never())->method('startImpersonation');
		$this->assertError($expected, $this->controller->impersonate('alice'));
	}

	public function testTargetNeverLoggedIn(): void {
		$this->loggedIn($this->user('admin'));
		$this->policy->method('mayImpersonateAnyone')->willReturn(true);
		$this->policy->method('isAdmin')->willReturn(true);
		$this->userManager->method('get')->willReturn($this->user('alice', 0));
		$this->policy->method('check')->willReturn(null);
		$this->util->expects($this->never())->method('startImpersonation');
		$this->assertError('userNeverLoggedIn', $this->controller->impersonate('alice'));
	}

	public function testSwitchFailure(): void {
		$this->loggedIn($this->user('admin'));
		$this->policy->method('mayImpersonateAnyone')->willReturn(true);
		$this->policy->method('isAdmin')->willReturn(true);
		$this->userManager->method('get')->willReturn($this->user('alice'));
		$this->policy->method('check')->willReturn(null);
		$this->util->method('startImpersonation')->willThrowException(new \RuntimeException('no session'));
		$this->auditTrail->expects($this->never())->method('started');
		$this->logger->expects($this->once())->method('logException');
		// Not the answer of a refusal: the session may have been logged out, the browser
		// reloads the page instead of offering a retry.
		$response = $this->controller->impersonate('alice');
		$this->assertSame(Http::STATUS_INTERNAL_SERVER_ERROR, $response->getStatus());
		$this->assertSame('switchFailed', $response->getData()['error']);
	}

	public function testSwitchFailureWithAnError(): void {
		$this->loggedIn($this->user('admin'));
		$this->policy->method('mayImpersonateAnyone')->willReturn(true);
		$this->policy->method('isAdmin')->willReturn(true);
		$this->userManager->method('get')->willReturn($this->user('alice'));
		$this->policy->method('check')->willReturn(null);
		$this->util->method('startImpersonation')->willThrowException(new \TypeError('unexpected'));
		$this->auditTrail->expects($this->never())->method('started');
		$this->assertSame(Http::STATUS_INTERNAL_SERVER_ERROR, $this->controller->impersonate('alice')->getStatus());
	}

	public static function credentialsProvider(): array {
		return [
			'Authorization header' => ['Basic YWRtaW46c2VjcmV0', []],
			'token authorization' => ['token abc', []],
			'HTTP Basic user handed over by PHP' => [null, ['PHP_AUTH_USER' => 'admin']],
			'HTTP Basic password handed over by PHP' => [null, ['PHP_AUTH_PW' => 'x']],
			'header under the name some web servers use' => [null, ['REDIRECT_HTTP_AUTHORIZATION' => 'Basic YWRtaW46c2VjcmV0']],
		];
	}

	/**
	 * A request that brings its own credentials is not the browser session of the
	 * impersonator - even if the platform gave it a session with a session token
	 * (it does for HTTP Basic requests that carry a cookie), and it does not need
	 * the CSRF token.
	 *
	 * @dataProvider credentialsProvider
	 */
	public function testARequestThatCarriesCredentialsCanNotStartAnImpersonation(?string $authorization, array $server): void {
		$this->authorization = $authorization;
		foreach ($server as $key => $value) {
			$_SERVER[$key] = $value;
		}
		$this->loggedIn($this->user('admin'));
		$this->policy->method('mayImpersonateAnyone')->willReturn(true);
		$this->policy->method('isAdmin')->willReturn(true);
		$this->userManager->method('get')->willReturn($this->user('alice'));
		$this->policy->method('check')->willReturn(null);
		$this->util->expects($this->never())->method('startImpersonation');
		$this->auditTrail->expects($this->never())->method('started');
		$this->logger->expects($this->once())->method('warning')->with(
			$this->stringContains('refused: an impersonation must be started from an interactive session'),
			$this->callback(function (array $context) {
				return $context['impersonator'] === 'admin';
			})
		);
		$this->assertError('cannotImpersonate', $this->controller->impersonate('alice'));
	}

	public function testStartFromANonInteractiveSessionIsRefusedAndLogged(): void {
		// e.g. a request that is only authenticated by HTTP Basic credentials
		$this->loggedIn($this->user('admin'));
		$this->policy->method('mayImpersonateAnyone')->willReturn(true);
		$this->policy->method('isAdmin')->willReturn(true);
		$this->userManager->method('get')->willReturn($this->user('alice'));
		$this->policy->method('check')->willReturn(null);
		$this->util->method('startImpersonation')->willThrowException(
			new RefusedException('an impersonation must be started from an interactive session')
		);
		$this->auditTrail->expects($this->never())->method('started');
		$this->logger->expects($this->once())->method('warning')->with(
			$this->stringContains('refused'),
			$this->callback(function (array $context) {
				return $context['impersonator'] === 'admin' && $context['target'] === 'alice'
					&& \strpos($context['reason'], 'interactive session') !== false;
			})
		);
		// the same answer as for every other refusal
		$this->assertError('cannotImpersonate', $this->controller->impersonate('alice'));
	}

	public function testImpersonate(): void {
		$admin = $this->user('admin');
		// the canonical uid is used even if the request used another spelling
		$alice = $this->user('alice');
		$this->loggedIn($admin);
		$this->policy->method('mayImpersonateAnyone')->willReturn(true);
		$this->policy->method('isAdmin')->willReturn(true);
		$this->userManager->method('get')->with('ALICE')->willReturn($alice);
		$this->policy->method('check')->with($admin, $alice)->willReturn(null);
		$this->util->expects($this->once())->method('startImpersonation')->with($alice, $admin);
		$this->auditTrail->expects($this->once())->method('started')->with('admin', 'alice');
		$response = $this->controller->impersonate('ALICE');
		$this->assertSame(Http::STATUS_OK, $response->getStatus());
		$this->assertSame([], $response->getData());
	}

	public function testARequestThatCarriesCredentialsStartsAnImpersonationOnlyIfTheOperatorAllowsThat(): void {
		// e.g. an instance behind a proxy that authenticates every request of the browser
		$this->authorization = 'Negotiate abc';
		$admin = $this->user('admin');
		$alice = $this->user('alice');
		$this->loggedIn($admin);
		$this->policy->method('allowsStartWithCredentials')->willReturn(true);
		$this->policy->method('mayImpersonateAnyone')->willReturn(true);
		$this->policy->method('isAdmin')->willReturn(true);
		$this->userManager->method('get')->willReturn($alice);
		$this->policy->method('check')->willReturn(null);
		$this->util->expects($this->once())->method('startImpersonation')->with($alice, $admin);
		$this->assertSame(Http::STATUS_OK, $this->controller->impersonate('alice')->getStatus());
	}

	private function asAdmin(): void {
		$this->loggedIn($this->user('admin'));
		$this->policy->method('isAdmin')->willReturn(true);
	}

	public function testSetPolicy(): void {
		$this->asAdmin();
		$stored = ['mode' => Policy::MODE_INCLUDE_GROUPS, 'groups' => ['g1'], 'allowGroupAdminTargets' => false];
		// what the server stored is the answer, not what was sent
		$this->policy->expects($this->once())->method('store')
			->with(Policy::MODE_INCLUDE_GROUPS, ['g1', 'gone'], false)->willReturn($stored);
		$this->logger->expects($this->once())->method('warning');
		$response = $this->controller->setPolicy(Policy::MODE_INCLUDE_GROUPS, ['g1', 'gone'], false);
		$this->assertSame(Http::STATUS_OK, $response->getStatus());
		$this->assertSame(['policy' => $stored], $response->getData());
	}

	public static function groupAdminTargetsProvider(): array {
		return [
			[true, true],
			['true', true],
			// everything else keeps the narrower policy, whatever a cast would make of it
			[false, false],
			['false', false],
			['yes', false],
			['1', false],
			[1, false],
			[[true], false],
			[null, false],
		];
	}

	/**
	 * @dataProvider groupAdminTargetsProvider
	 *
	 * @param mixed $sent
	 */
	public function testSetPolicyOnlyTakesTrueForTheGroupAdminTargets($sent, bool $stored): void {
		$this->asAdmin();
		$this->policy->expects($this->once())->method('store')->with(Policy::MODE_ADMINS, [], $stored)
			->willReturn(['mode' => Policy::MODE_ADMINS, 'groups' => [], 'allowGroupAdminTargets' => $stored]);
		$this->controller->setPolicy(Policy::MODE_ADMINS, [], $sent);
	}

	public static function notAllowedToSetThePolicyProvider(): array {
		return [
			'anonymous' => [false, false, false],
			'normal user or group admin' => [true, false, false],
			'administrator who impersonates' => [true, true, true],
		];
	}

	/**
	 * @dataProvider notAllowedToSetThePolicyProvider
	 */
	public function testSetPolicyIsForAdministratorsOnly(bool $loggedIn, bool $isAdmin, bool $impersonating): void {
		$this->loggedIn($loggedIn ? $this->user('someone') : null);
		$this->policy->method('isAdmin')->willReturn($isAdmin);
		$this->util->method('isImpersonating')->willReturn($impersonating);
		$this->policy->expects($this->never())->method('store');
		$response = $this->controller->setPolicy(Policy::MODE_ALL_GROUP_ADMINS, [], true);
		$this->assertSame(Http::STATUS_FORBIDDEN, $response->getStatus());
		$this->assertSame(['error' => 'forbidden'], $response->getData());
	}

	public function testSetPolicyWithAnUnknownMode(): void {
		$this->asAdmin();
		$current = ['mode' => Policy::MODE_ADMINS, 'groups' => [], 'allowGroupAdminTargets' => false];
		$this->policy->method('describe')->willReturn($current);
		$this->policy->method('store')->willThrowException(new \InvalidArgumentException('Unknown delegation mode'));
		$response = $this->controller->setPolicy('everybody', [], false);
		$this->assertSame(Http::STATUS_BAD_REQUEST, $response->getStatus());
		$this->assertSame(['error' => 'invalidPolicy', 'policy' => $current], $response->getData());
	}

	public function testSetPolicyWithMalformedParameters(): void {
		$this->asAdmin();
		$this->policy->method('describe')->willReturn(['mode' => Policy::MODE_ADMINS, 'groups' => [], 'allowGroupAdminTargets' => false]);
		$this->policy->expects($this->never())->method('store');
		$this->assertSame(Http::STATUS_BAD_REQUEST, $this->controller->setPolicy(['admins'], [], false)->getStatus());
		$this->assertSame(Http::STATUS_BAD_REQUEST, $this->controller->setPolicy(Policy::MODE_INCLUDE_GROUPS, 'g1', false)->getStatus());
	}

	public function testSetPolicyThatCanNotBeStored(): void {
		$this->asAdmin();
		$this->policy->method('store')->willThrowException(new \RuntimeException('database down'));
		$this->logger->expects($this->once())->method('logException');
		$response = $this->controller->setPolicy(Policy::MODE_ADMINS, [], false);
		$this->assertSame(Http::STATUS_INTERNAL_SERVER_ERROR, $response->getStatus());
		$this->assertSame(['error' => 'notSaved'], $response->getData());
	}
}
