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

use OCA\Impersonate\Notifier;
use OCP\IL10N;
use OCP\IURLGenerator;
use OCP\L10N\IFactory;
use OCP\Notification\INotification;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

class NotifierTest extends TestCase {
	/** @var Notifier */
	private $notifier;

	protected function setUp(): void {
		parent::setUp();
		$l10n = $this->createMock(IL10N::class);
		$l10n->method('t')->willReturnCallback(function ($text, $parameters = []) {
			return \vsprintf($text, $parameters);
		});
		$factory = $this->createMock(IFactory::class);
		$factory->method('get')->with('impersonate', 'de')->willReturn($l10n);
		$urlGenerator = $this->createMock(IURLGenerator::class);
		$urlGenerator->method('getAbsoluteURL')->willReturnCallback(function ($url) {
			return 'https://cloud.example.org' . $url;
		});
		$this->notifier = new Notifier($factory, $urlGenerator);
	}

	/**
	 * @return INotification|MockObject
	 */
	private function notification(string $app, string $subject, array $parameters) {
		$notification = $this->createMock(INotification::class);
		$notification->method('getApp')->willReturn($app);
		$notification->method('getSubject')->willReturn($subject);
		$notification->method('getSubjectParameters')->willReturn($parameters);
		return $notification;
	}

	public function testPrepare(): void {
		$notification = $this->notification('impersonate', Notifier::SUBJECT_CREDENTIAL_REVOKED, ['Phone']);
		$notification->expects($this->once())->method('setParsedSubject')->with(
			$this->logicalAnd($this->stringContains('"Phone" was revoked'), $this->stringContains('impersonation'))
		)->willReturnSelf();
		// a notification without a link is not rendered properly by the notifications app
		$notification->expects($this->once())->method('setLink')
			->with('https://cloud.example.org/index.php/settings/personal?sectionid=security')->willReturnSelf();
		$this->assertSame($notification, $this->notifier->prepare($notification, 'de'));
	}

	public function testPrepareWithoutParameters(): void {
		$notification = $this->notification('impersonate', Notifier::SUBJECT_CREDENTIAL_REVOKED, []);
		$notification->expects($this->once())->method('setParsedSubject')->with($this->stringContains('"" was revoked'))->willReturnSelf();
		$this->notifier->prepare($notification, 'de');
	}

	public static function foreignProvider(): array {
		return [
			'another app' => ['files_sharing', Notifier::SUBJECT_CREDENTIAL_REVOKED],
			'unknown subject' => ['impersonate', 'something_else'],
		];
	}

	/**
	 * The notification manager asks every notifier: what is not ours must be refused.
	 *
	 * @dataProvider foreignProvider
	 */
	public function testNotificationsOfOthersAreRefused(string $app, string $subject): void {
		$notification = $this->notification($app, $subject, ['Phone']);
		$notification->expects($this->never())->method('setParsedSubject');
		$this->expectException(\InvalidArgumentException::class);
		$this->notifier->prepare($notification, 'de');
	}
}
