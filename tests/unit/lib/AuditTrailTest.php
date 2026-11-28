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

use OCA\Impersonate\AuditTrail;
use OCA\Impersonate\Notifier;
use OCP\ILogger;
use OCP\Notification\IManager;
use OCP\Notification\INotification;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\EventDispatcher\GenericEvent;
use Test\TestCase;

class AuditTrailTest extends TestCase {
	/** @var EventDispatcherInterface|MockObject */
	private $eventDispatcher;
	/** @var IManager|MockObject */
	private $notificationManager;
	/** @var ILogger|MockObject */
	private $logger;
	/** @var AuditTrail */
	private $auditTrail;

	protected function setUp(): void {
		parent::setUp();
		$this->eventDispatcher = $this->createMock(EventDispatcherInterface::class);
		$this->notificationManager = $this->createMock(IManager::class);
		$this->logger = $this->createMock(ILogger::class);
		$this->auditTrail = new AuditTrail($this->eventDispatcher, $this->notificationManager, $this->logger);
	}

	private function expectEvent(string $name, array $arguments): void {
		$this->eventDispatcher->expects($this->once())->method('dispatch')->with(
			$this->callback(function (GenericEvent $event) use ($arguments) {
				return $event->getArguments() === $arguments;
			}),
			$name
		)->willReturnArgument(0);
	}

	public function testStarted(): void {
		// the event other apps have been listening to
		$this->expectEvent('user.afterimpersonate', ['impersonator' => 'admin', 'targetUser' => 'alice']);
		$this->auditTrail->started('admin', 'alice');
	}

	public function testEnded(): void {
		$this->expectEvent(
			'user.afterimpersonatelogout',
			['impersonator' => 'admin', 'targetUser' => 'alice', 'reason' => 'the reason']
		);
		$this->auditTrail->ended('admin', 'alice', 'the reason');
	}

	public function testAFailingConsumerDoesNotChangeTheOutcome(): void {
		$this->eventDispatcher->method('dispatch')->willThrowException(new \RuntimeException('audit app broken'));
		$notification = $this->createMock(INotification::class);
		foreach (['setApp', 'setUser', 'setDateTime', 'setObject', 'setSubject'] as $setter) {
			$notification->method($setter)->willReturnSelf();
		}
		$this->notificationManager->method('createNotification')->willReturn($notification);
		// the account owner is told even if the audit app is broken
		$this->notificationManager->expects($this->once())->method('notify');
		$this->logger->expects($this->exactly(3))->method('logException');
		$this->auditTrail->started('admin', 'alice');
		$this->auditTrail->ended('admin', 'alice', 'the reason');
		$this->auditTrail->credentialRevoked('alice', 'Phone', 'admin');
		$this->addToAssertionCount(1);
	}

	public function testAFailingConsumerThatThrowsAnErrorIsIsolatedAsWell(): void {
		$this->eventDispatcher->method('dispatch')->willThrowException(new \TypeError('audit app broken'));
		$this->logger->expects($this->once())->method('logException');
		$this->auditTrail->started('admin', 'alice');
	}

	public function testCredentialRevokedTellsAuditAppsAndTheAccountOwner(): void {
		$this->expectEvent(
			'user.impersonate.credentialrevoked',
			['targetUser' => 'alice', 'credential' => 'Phone', 'impersonator' => 'admin']
		);
		$notification = $this->createMock(INotification::class);
		$notification->expects($this->once())->method('setApp')->with('impersonate')->willReturnSelf();
		// the owner of the account, not the impersonator
		$notification->expects($this->once())->method('setUser')->with('alice')->willReturnSelf();
		$notification->expects($this->once())->method('setDateTime')->willReturnSelf();
		$notification->expects($this->once())->method('setObject')->with(
			'credential',
			$this->callback(function ($id) {
				return \is_string($id) && \strlen($id) <= 64 && $id !== '';
			})
		)->willReturnSelf();
		$notification->expects($this->once())->method('setSubject')
			->with(Notifier::SUBJECT_CREDENTIAL_REVOKED, ['Phone', Notifier::CREDENTIAL_APP_PASSWORD])->willReturnSelf();
		$this->notificationManager->method('createNotification')->willReturn($notification);
		$this->notificationManager->expects($this->once())->method('notify')->with($notification);
		$this->auditTrail->credentialRevoked('alice', 'Phone', 'admin');
	}

	public static function kindProvider(): array {
		return [
			// kind, name, what the event calls the credential (as version 1.0.1 did)
			'app password' => [Notifier::CREDENTIAL_APP_PASSWORD, 'Phone', 'Phone'],
			'session' => [Notifier::CREDENTIAL_SESSION, 'Firefox', 'session Firefox'],
			'URL signing key' => [Notifier::CREDENTIAL_SIGNING_KEY, '', 'URL signing key'],
		];
	}

	/**
	 * The event keeps its English label for audit apps; the notification gets the name and the kind
	 * separately, so that its text is a translation as a whole (Notifier).
	 *
	 * @dataProvider kindProvider
	 */
	public function testTheKindOfTheCredentialTravelsWithTheNotification(string $kind, string $name, string $label): void {
		$this->expectEvent(
			'user.impersonate.credentialrevoked',
			['targetUser' => 'alice', 'credential' => $label, 'impersonator' => 'admin']
		);
		$notification = $this->createMock(INotification::class);
		foreach (['setApp', 'setUser', 'setDateTime', 'setObject'] as $setter) {
			$notification->method($setter)->willReturnSelf();
		}
		$notification->expects($this->once())->method('setSubject')
			->with(Notifier::SUBJECT_CREDENTIAL_REVOKED, [$name, $kind])->willReturnSelf();
		$this->notificationManager->method('createNotification')->willReturn($notification);
		$this->notificationManager->expects($this->once())->method('notify')->with($notification);
		$this->auditTrail->credentialRevoked('alice', $name, 'admin', $kind);
	}

	public function testANotificationThatCanNotBeSentIsOnlyLogged(): void {
		$this->eventDispatcher->expects($this->once())->method('dispatch')->willReturnArgument(0);
		$this->notificationManager->method('createNotification')->willThrowException(new \RuntimeException('no notifications'));
		$this->logger->expects($this->once())->method('logException');
		$this->auditTrail->credentialRevoked('alice', 'Phone', null);
	}

	public function testStartAndEndCarryTheIdOfTheImpersonation(): void {
		// an audit app pairs the start and the end of one impersonation by it
		$events = [];
		$dispatcher = $this->createMock(EventDispatcherInterface::class);
		$dispatcher->method('dispatch')->willReturnCallback(function (GenericEvent $event, $name) use (&$events) {
			$events[] = [$name, $event->getArguments()];
			return $event;
		});
		$trail = new AuditTrail($dispatcher, $this->createMock(IManager::class), $this->createMock(ILogger::class));
		$trail->started('admin', 'alice', 'abcdefgh12345678');
		$trail->ended('admin', 'alice', 'the reason', 'abcdefgh12345678');
		$trail->ended('admin', 'alice', 'switched by an older version');
		$this->assertSame([
			[AuditTrail::EVENT_START, ['impersonator' => 'admin', 'targetUser' => 'alice', 'impersonation' => 'abcdefgh12345678']],
			[AuditTrail::EVENT_END, ['impersonator' => 'admin', 'targetUser' => 'alice', 'reason' => 'the reason', 'impersonation' => 'abcdefgh12345678']],
			[AuditTrail::EVENT_END, ['impersonator' => 'admin', 'targetUser' => 'alice', 'reason' => 'switched by an older version']],
		], $events);
	}

	public function testEveryRevokedCredentialGetsANotificationOfItsOwn(): void {
		// two app passwords with the same name are two notifications for the owner
		$objects = [];
		$notification = $this->createMock(INotification::class);
		foreach (['setApp', 'setUser', 'setDateTime', 'setSubject'] as $setter) {
			$notification->method($setter)->willReturnSelf();
		}
		$notification->method('setObject')->willReturnCallback(function ($type, $id) use (&$objects, $notification) {
			$objects[] = [$type, $id];
			return $notification;
		});
		$manager = $this->createMock(IManager::class);
		$manager->method('createNotification')->willReturn($notification);
		$trail = new AuditTrail($this->createMock(EventDispatcherInterface::class), $manager, $this->createMock(ILogger::class));
		$trail->credentialRevoked('alice', 'phone', 'admin', Notifier::CREDENTIAL_APP_PASSWORD, 70);
		$trail->credentialRevoked('alice', 'phone', 'admin', Notifier::CREDENTIAL_APP_PASSWORD, 71);
		$trail->credentialRevoked('alice', 'phone', 'admin', Notifier::CREDENTIAL_APP_PASSWORD, 70);
		$this->assertCount(3, $objects);
		$this->assertSame('credential', $objects[0][0]);
		$this->assertNotSame($objects[0][1], $objects[1][1]);
		$this->assertSame($objects[0][1], $objects[2][1], 'the same token is the same object');
		$this->assertSame(32, \strlen($objects[0][1]));
	}
}
