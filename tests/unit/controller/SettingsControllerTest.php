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

use OCA\Impersonate\Controller\SettingsController;
use OCA\Impersonate\Policy;
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
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\EventDispatcher\GenericEvent;
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
	/** @var EventDispatcherInterface|MockObject */
	private $eventDispatcher;
	/** @var SettingsController */
	private $controller;
	/** @var string */
	private $appEnabled = 'yes';

	protected function setUp(): void {
		parent::setUp();
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
		$this->eventDispatcher = $this->createMock(EventDispatcherInterface::class);
		$request = $this->createMock(IRequest::class);
		$request->method('getRemoteAddress')->willReturn('10.0.0.1');
		$this->controller = new SettingsController(
			'impersonate',
			$request,
			$this->userManager,
			$this->userSession,
			$this->createMock(ILogger::class),
			$this->config,
			$l10n,
			$this->policy,
			$this->util,
			$this->eventDispatcher
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
		$this->policy->method('isIncludeGroupsMode')->willReturn(true);
		$this->policy->method('isAllGroupAdminsMode')->willReturn(false);
		$this->assertSame(['["g1"]', 'true', 'false', false, true, '["dave"]'], $this->controller->getDataForImpersonateApp()->getData());
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
		$this->eventDispatcher->expects($this->never())->method('dispatch');
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
		$this->eventDispatcher->expects($this->once())->method('dispatch')->with(
			$this->callback(function (GenericEvent $e) {
				return $e->getArgument('impersonator') === 'admin' && $e->getArgument('targetUser') === 'alice';
			}),
			'user.afterimpersonate'
		);
		$response = $this->controller->impersonate('ALICE');
		$this->assertSame(Http::STATUS_OK, $response->getStatus());
		$this->assertSame([], $response->getData());
	}
}
