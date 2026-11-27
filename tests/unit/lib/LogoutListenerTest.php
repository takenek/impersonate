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

use OCA\Impersonate\LogoutListener;
use OCA\Impersonate\Util;
use OCP\ILogger;
use OCP\IRequest;
use OCP\IUser;
use OCP\IUserSession;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Component\EventDispatcher\GenericEvent;
use Test\TestCase;

class LogoutListenerTest extends TestCase {
	/** @var Util|MockObject */
	private $util;
	/** @var IUserSession|MockObject */
	private $userSession;
	/** @var IRequest|MockObject */
	private $request;
	/** @var ILogger|MockObject */
	private $logger;
	/** @var LogoutListener */
	private $listener;

	protected function setUp(): void {
		parent::setUp();
		$this->util = $this->createMock(Util::class);
		$this->userSession = $this->createMock(IUserSession::class);
		$alice = $this->createMock(IUser::class);
		$alice->method('getUID')->willReturn('alice');
		$this->userSession->method('getUser')->willReturn($alice);
		$this->request = $this->createMock(IRequest::class);
		$this->request->method('getRemoteAddress')->willReturn('10.0.0.1');
		$this->logger = $this->createMock(ILogger::class);
		$this->listener = new LogoutListener(
			$this->util,
			$this->userSession,
			$this->request,
			$this->logger
		);
	}

	private function request(string $method, string $path, bool $csrfOk = true): void {
		$this->request->method('getMethod')->willReturn($method);
		$this->request->method('getPathInfo')->willReturn($path);
		$this->request->method('getRawPathInfo')->willReturn($path);
		$this->request->method('passesCSRFCheck')->willReturn($csrfOk);
	}

	public function testNotImpersonating(): void {
		$this->util->method('getImpersonatorUid')->willReturn(null);
		$this->util->expects($this->never())->method('stopImpersonation');
		$this->util->expects($this->never())->method('endImpersonation');
		$event = new GenericEvent(null, ['cancel' => false]);
		$this->listener->onPreLogout($event);
		$this->assertFalse($event->getArgument('cancel'));
	}

	public function testEventWithoutCancelArgumentIsIgnored(): void {
		$this->util->method('getImpersonatorUid')->willReturn('admin');
		$this->util->expects($this->never())->method('stopImpersonation');
		$this->util->expects($this->never())->method('endImpersonation');
		$this->listener->onPreLogout(new GenericEvent(null, []));
	}

	public function testUserLogoutSwitchesBack(): void {
		$this->util->method('getImpersonatorUid')->willReturn('admin');
		$this->request('GET', '/logout');
		// Util announces the end itself, for every way an impersonation ends
		$this->util->expects($this->once())->method('stopImpersonation')->willReturn(true);
		$this->util->expects($this->never())->method('endImpersonation');
		$this->logger->expects($this->once())->method('warning')->with(
			$this->stringContains('stopped impersonating'),
			$this->callback(function (array $context) {
				return $context['impersonator'] === 'admin' && $context['target'] === 'alice' && $context['remote'] === '10.0.0.1';
			})
		);
		$event = new GenericEvent(null, ['cancel' => false]);
		$this->listener->onPreLogout($event);
		$this->assertTrue($event->getArgument('cancel'));
	}

	public function testUserLogoutThatCanNotSwitchBackLogsOut(): void {
		$this->util->method('getImpersonatorUid')->willReturn('admin');
		$this->request('GET', '/logout');
		$this->util->expects($this->once())->method('stopImpersonation')->willReturn(false);
		$this->util->expects($this->once())->method('endImpersonation')->with(Util::REASON_LOGOUT);
		$event = new GenericEvent(null, ['cancel' => false]);
		$this->listener->onPreLogout($event);
		$this->assertFalse($event->getArgument('cancel'));
	}

	public static function forcedLogoutProvider(): array {
		return [
			'session validation' => ['GET', '/apps/files/', true],
			'dav request' => ['PROPFIND', '/remote.php/webdav/', true],
			'post to logout' => ['POST', '/logout', true],
			'logout without CSRF token' => ['GET', '/logout', false],
		];
	}

	/**
	 * @dataProvider forcedLogoutProvider
	 */
	public function testForcedLogoutEndsTheImpersonation(string $method, string $path, bool $csrfOk): void {
		$this->util->method('getImpersonatorUid')->willReturn('admin');
		$this->request($method, $path, $csrfOk);
		$this->util->expects($this->never())->method('stopImpersonation');
		$this->util->expects($this->once())->method('endImpersonation')->with(Util::REASON_LOGOUT);
		$event = new GenericEvent(null, ['cancel' => false]);
		$this->listener->onPreLogout($event);
		$this->assertFalse($event->getArgument('cancel'));
	}

	public function testTheRecordedTargetIsLoggedEvenIfTheSessionHasNoUserAnymore(): void {
		$userSession = $this->createMock(IUserSession::class);
		$userSession->method('getUser')->willReturn(null);
		$this->util->method('getImpersonatorUid')->willReturn('admin');
		$this->util->method('getTargetUid')->willReturn('alice');
		$this->request('GET', '/apps/files/');
		$this->logger->expects($this->once())->method('warning')->with(
			$this->anything(),
			$this->callback(function (array $context) {
				return $context['target'] === 'alice';
			})
		);
		$listener = new LogoutListener($this->util, $userSession, $this->request, $this->logger);
		$listener->onPreLogout(new GenericEvent(null, ['cancel' => false]));
	}

	public function testALogoutWhosePathCanNotBeDeterminedIsNotASwitchBack(): void {
		$this->util->method('getImpersonatorUid')->willReturn('admin');
		$this->request->method('getMethod')->willReturn('GET');
		$this->request->method('getRawPathInfo')->willThrowException(new \Exception('unknown path'));
		$this->request->method('passesCSRFCheck')->willReturn(true);
		$this->util->expects($this->never())->method('stopImpersonation');
		$this->util->expects($this->once())->method('endImpersonation');
		$event = new GenericEvent(null, ['cancel' => false]);
		$this->listener->onPreLogout($event);
		$this->assertFalse($event->getArgument('cancel'));
	}
}
