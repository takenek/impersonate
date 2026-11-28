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

	public static function kindProvider(): array {
		return [
			'app password' => [['Phone', Notifier::CREDENTIAL_APP_PASSWORD], '"Phone" was revoked', null],
			// nothing untranslated is put into the sentence: no "session ..." label, no "URL signing key" label
			'session' => [['Firefox', Notifier::CREDENTIAL_SESSION], 'The session "Firefox" of your account was ended', '"session'],
			'URL signing key' => [['', Notifier::CREDENTIAL_SIGNING_KEY], 'The URL signing key of your account was removed', '""'],
			'unknown kind' => [['Phone', 'something new'], '"Phone" was revoked', null],
			// as version 1.0.1 stored them: one parameter, the whole label
			'stored by 1.0.1: session' => [['session Firefox'], '"session Firefox" was revoked', null],
			'stored by 1.0.1: URL signing key' => [['URL signing key'], '"URL signing key" was revoked', null],
		];
	}

	/**
	 * @dataProvider kindProvider
	 */
	public function testEveryKindOfCredentialHasASentenceOfItsOwn(array $parameters, string $expected, ?string $notExpected): void {
		$notification = $this->notification('impersonate', Notifier::SUBJECT_CREDENTIAL_REVOKED, $parameters);
		$notification->expects($this->once())->method('setParsedSubject')->with(
			$this->callback(function ($subject) use ($expected, $notExpected) {
				return \is_string($subject)
					&& \strpos($subject, $expected) === 0
					&& \strpos($subject, 'impersonation of your account') !== false
					&& ($notExpected === null || \strpos($subject, $notExpected) === false);
			})
		)->willReturnSelf();
		$notification->expects($this->once())->method('setLink')->willReturnSelf();
		$this->notifier->prepare($notification, 'de');
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

	public function testANameStoredByAnEarlierVersionIsShownAsPlainText(): void {
		// up to 1.0.3 the name was stored as its client gave it
		$notification = $this->notification('impersonate', Notifier::SUBJECT_CREDENTIAL_REVOKED, ["evil\nname\u{202E}gnp.exe", Notifier::CREDENTIAL_SESSION]);
		$notification->expects($this->once())->method('setParsedSubject')->with($this->callback(function (string $subject) {
			return \strpos($subject, '"evil namegnp.exe"') !== false && \preg_match('/[\x00-\x1F]|\x{202E}/u', $subject) === 0;
		}));
		$this->notifier->prepare($notification, 'de');
	}
}
