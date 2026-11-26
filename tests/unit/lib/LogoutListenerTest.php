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
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\EventDispatcher\GenericEvent;
use Test\TestCase;

class LogoutListenerTest extends TestCase {
	/** @var Util|MockObject */
	private $util;
	/** @var IUserSession|MockObject */
	private $userSession;
	/** @var IRequest|MockObject */
	private $request;
	/** @var EventDispatcherInterface|MockObject */
	private $eventDispatcher;
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
		$this->eventDispatcher = $this->createMock(EventDispatcherInterface::class);
		$this->logger = $this->createMock(ILogger::class);
		$this->listener = new LogoutListener(
			$this->util,
			$this->userSession,
			$this->request,
			$this->eventDispatcher,
			$this->logger
		);
	}

	private function request(string $method, string $path, bool $csrfOk = true): void {
		$this->request->method('getMethod')->willReturn($method);
		$this->request->method('getPathInfo')->willReturn($path);
		$this->request->method('getRawPathInfo')->willReturn($path);
		$this->request->method('passesCSRFCheck')->willReturn($csrfOk);
	}

	private function expectStopEvent(): void {
		$this->eventDispatcher->expects($this->once())->method('dispatch')->with(
			$this->callback(function (GenericEvent $e) {
				return $e->getArgument('impersonator') === 'admin' && $e->getArgument('targetUser') === 'alice';
			}),
			'user.afterimpersonatelogout'
		);
	}

	public function testNotImpersonating(): void {
		$this->util->method('getImpersonatorUid')->willReturn(null);
		$this->util->expects($this->never())->method('stopImpersonation');
		$this->util->expects($this->never())->method('endImpersonation');
		$this->eventDispatcher->expects($this->never())->method('dispatch');
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
		$this->util->expects($this->once())->method('stopImpersonation')->willReturn(true);
		$this->util->expects($this->never())->method('endImpersonation');
		$this->expectStopEvent();
		$event = new GenericEvent(null, ['cancel' => false]);
		$this->listener->onPreLogout($event);
		$this->assertTrue($event->getArgument('cancel'));
	}

	public function testUserLogoutThatCanNotSwitchBackLogsOut(): void {
		$this->util->method('getImpersonatorUid')->willReturn('admin');
		$this->request('GET', '/logout');
		$this->util->expects($this->once())->method('stopImpersonation')->willReturn(false);
		$this->util->expects($this->once())->method('endImpersonation');
		$this->expectStopEvent();
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
		$this->util->expects($this->once())->method('endImpersonation');
		$this->expectStopEvent();
		$event = new GenericEvent(null, ['cancel' => false]);
		$this->listener->onPreLogout($event);
		$this->assertFalse($event->getArgument('cancel'));
	}
}
