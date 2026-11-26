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

use OCA\Impersonate\ImpersonationGuard;
use OCA\Impersonate\Policy;
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
	/** @var ImpersonationGuard */
	private $guard;

	protected function setUp(): void {
		parent::setUp();
		$this->util = $this->createMock(Util::class);
		$this->policy = $this->createMock(Policy::class);
		$this->userSession = $this->createMock(IUserSession::class);
		$this->userManager = $this->createMock(IUserManager::class);
		$this->request = $this->createMock(IRequest::class);
		$this->guard = new ImpersonationGuard(
			$this->util,
			$this->policy,
			$this->userSession,
			$this->userManager,
			$this->request,
			$this->createMock(ILogger::class)
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

	public function testNothingToDoWithoutImpersonation(): void {
		$this->util->method('getImpersonatorUid')->willReturn(null);
		$this->userSession->expects($this->never())->method('logout');
		$this->assertTrue($this->guard->validate());
	}

	public function testValidImpersonation(): void {
		$this->util->method('getImpersonatorUid')->willReturn('admin');
		$this->userSession->method('getUser')->willReturn($this->user('alice'));
		$this->userManager->method('get')->with('admin')->willReturn($this->user('admin'));
		$this->policy->method('check')->willReturn(null);
		$this->util->expects($this->once())->method('touchParkedToken')->willReturn(true);
		$this->util->expects($this->never())->method('endImpersonation');
		$this->userSession->expects($this->never())->method('logout');
		$this->assertTrue($this->guard->validate());
	}

	public static function invalidProvider(): array {
		return [
			'impersonator deleted' => [null, null, true],
			'impersonator disabled' => [false, null, true],
			'permission revoked' => [true, Policy::ERROR_CANNOT_IMPERSONATE, true],
			'parked session revoked' => [true, null, false],
		];
	}

	/**
	 * @dataProvider invalidProvider
	 */
	public function testInvalidImpersonationLogsOut(?bool $impersonatorEnabled, ?string $policyError, bool $parkedOk): void {
		$this->util->method('getImpersonatorUid')->willReturn('admin');
		$this->userSession->method('getUser')->willReturn($this->user('alice'));
		$this->userManager->method('get')->willReturn(
			$impersonatorEnabled === null ? null : $this->user('admin', $impersonatorEnabled)
		);
		$this->policy->method('check')->willReturn($policyError);
		$this->util->method('touchParkedToken')->willReturn($parkedOk);
		$this->util->expects($this->once())->method('endImpersonation');
		$this->userSession->expects($this->once())->method('logout');
		$this->assertFalse($this->guard->validate());
	}

	public function testImpersonatedUserGone(): void {
		$this->util->method('getImpersonatorUid')->willReturn('admin');
		$this->userSession->method('getUser')->willReturn(null);
		$this->util->expects($this->once())->method('endImpersonation');
		$this->userSession->expects($this->once())->method('logout');
		$this->assertFalse($this->guard->validate());
	}

	public static function requestProvider(): array {
		return [
			[true, 'POST', '/settings/personal/authtokens', null, true],
			[true, 'POST', '/settings/personal/authtokens/', null, true],
			[true, 'POST', '//settings/personal/authtokens', null, true],
			[true, 'POST', '/settings//personal/authtokens', null, true],
			[true, 'POST', '/settings/personal/authtoken%73', null, true],
			[true, 'POST', '/settings/personal/authtokens', '//settings/personal/authtokens', true],
			[true, 'GET', '/settings/personal/authtokens', null, false],
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
		];
	}

	/**
	 * @dataProvider requestProvider
	 */
	public function testIsForbiddenRequest(bool $impersonating, string $method, string $raw, ?string $decoded, bool $forbidden): void {
		$this->util->method('isImpersonating')->willReturn($impersonating);
		$this->request->method('getMethod')->willReturn($method);
		$this->request->method('getRawPathInfo')->willReturn($raw);
		$this->request->method('getPathInfo')->willReturn($decoded ?? \rawurldecode($raw));
		$this->assertSame($forbidden, $this->guard->isForbiddenRequest());
	}

	public function testNormalizedPath(): void {
		$this->request->method('getRawPathInfo')->willReturn('//logout/');
		$this->request->method('getPathInfo')->willReturn('//logout/');
		$this->assertSame('/logout', ImpersonationGuard::normalizedPath($this->request));
	}
}
