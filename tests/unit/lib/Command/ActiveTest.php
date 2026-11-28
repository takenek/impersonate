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

namespace OCA\Impersonate\Tests\Unit\Lib\Command;

use OCA\Impersonate\Command\Active;
use OCA\Impersonate\Reconciler;
use OCP\IConfig;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Component\Console\Tester\CommandTester;
use Test\TestCase;

class ActiveTest extends TestCase {
	private const ACTIVE = [
		'a' => ['impersonator' => 'admin', 'target' => 'alice', 'token' => 60, 'signingKey' => false, 'start' => 1700000000],
		'b' => ['impersonator' => 'carol', 'target' => 'bob', 'token' => 61, 'signingKey' => false, 'start' => 1700000300],
	];

	/** @var Reconciler|MockObject */
	private $reconciler;
	/** @var CommandTester */
	private $tester;
	/** @var string app config "enabled" of the app */
	private $enabled = 'yes';
	/** @var bool */
	private $blocked = false;
	/** @var string[] the calls to the reconciler, in their order */
	private $calls = [];

	protected function setUp(): void {
		parent::setUp();
		$this->reconciler = $this->createMock(Reconciler::class);
		$this->reconciler->method('startsBlocked')->willReturnCallback(function () {
			return $this->blocked;
		});
		$this->reconciler->method('blockStarts')->willReturnCallback(function (bool $blocked) {
			$this->calls[] = $blocked ? 'block' : 'unblock';
			$this->blocked = $blocked;
		});
		$config = $this->createMock(IConfig::class);
		$config->method('getAppValue')->willReturnCallback(function ($app, $key, $default = '') {
			return $app === 'impersonate' && $key === 'enabled' ? $this->enabled : $default;
		});
		$this->tester = new CommandTester(new Active($this->reconciler, $config));
	}

	public function testNoActiveImpersonations(): void {
		$this->reconciler->method('getActive')->willReturn([]);
		// what is over anyway is finished first, nothing is ended by force
		$this->reconciler->expects($this->once())->method('run')->with(false);
		// listing leaves the background job and the block alone
		$this->reconciler->expects($this->never())->method('releaseJobIfIdle');
		$this->reconciler->expects($this->never())->method('blockStarts');
		$this->assertSame(0, $this->tester->execute([]));
		$this->assertSame('No active impersonations.', \trim($this->tester->getDisplay()));
	}

	public function testEndWithNothingActiveStillReleasesTheBackgroundJob(): void {
		// the last step before the app is disabled: nothing of it stays on the job list
		$this->reconciler->method('getActive')->willReturn([]);
		$this->reconciler->expects($this->once())->method('run')->with(false);
		$this->reconciler->expects($this->once())->method('releaseJobIfIdle');
		$this->assertSame(0, $this->tester->execute(['--end' => true]));
	}

	public function testList(): void {
		$this->reconciler->method('getActive')->willReturn(self::ACTIVE);
		$this->reconciler->expects($this->once())->method('run')->with(false);
		$this->assertSame(0, $this->tester->execute([]));
		$output = $this->tester->getDisplay();
		$this->assertStringContainsString('admin impersonates alice since ' . \date('c', 1700000000), $output);
		$this->assertStringContainsString('carol impersonates bob since ', $output);
		$this->assertStringNotContainsString('Ended', $output);
	}

	private const PENDING = [
		'aaaaaaaaaaaaaaaa' => ['impersonator' => 'admin', 'target' => 'alice', 'token' => 60, 'signingKey' => false, 'start' => 1700000000, 'pending' => true, 'ended' => 1700000600],
		'bbbbbbbbbbbbbbbb' => ['impersonator' => 'carol', 'target' => 'bob', 'token' => 61, 'signingKey' => true, 'start' => 1700000000, 'pending' => true, 'ended' => 1700000700, 'tokenRevoked' => true],
	];

	public function testListNamesWhatWaitsForItsCleanup(): void {
		$this->reconciler->method('getActive')->willReturn([]);
		$this->reconciler->method('getPending')->willReturn(self::PENDING);
		$this->assertSame(0, $this->tester->execute([]), 'listing is no gate');
		$output = $this->tester->getDisplay();
		$this->assertStringContainsString('The cleanup after 2 impersonation(s) is not complete yet', $output);
		$this->assertStringContainsString('The session token of 1 of them is not known to be revoked yet', $output);
		// each with what an operator needs to decide about it
		$this->assertStringContainsString('record active_aaaaaaaaaaaaaaaa: admin impersonated alice, ended ' . \date('c', 1700000600) . ', session token not known to be revoked', $output);
		$this->assertStringContainsString('record active_bbbbbbbbbbbbbbbb: carol impersonated bob, ended ' . \date('c', 1700000700) . ', session token revoked', $output);
	}

	public function testEnd(): void {
		// what counts afterwards is what the database says now
		$this->reconciler->method('getActive')->willReturnOnConsecutiveCalls(self::ACTIVE, []);
		$this->reconciler->expects($this->exactly(2))->method('run')->withConsecutive([false], [true])
			->willReturnOnConsecutiveCalls(0, 2);
		$this->reconciler->expects($this->once())->method('releaseJobIfIdle');
		$this->assertSame(0, $this->tester->execute(['--end' => true]));
		$output = $this->tester->getDisplay();
		$this->assertStringContainsString('Ended 2 impersonation(s).', $output);
		$this->assertStringNotContainsString('not complete', $output);
		// nothing kept new impersonations from starting: the operator is told
		$this->assertStringContainsString('New impersonations can still be started: --block prevents that', $output);
	}

	public function testEndThatLeavesACleanupToTheBackgroundJobIsNoSuccess(): void {
		$this->reconciler->method('getActive')->willReturnOnConsecutiveCalls(self::ACTIVE, []);
		$this->reconciler->method('run')->willReturnOnConsecutiveCalls(0, 2);
		$this->reconciler->method('getPending')->willReturn(['aaaaaaaaaaaaaaaa' => self::PENDING['aaaaaaaaaaaaaaaa']]);
		$this->assertSame(Active::EXIT_PENDING, $this->tester->execute(['--end' => true]));
		$output = $this->tester->getDisplay();
		$this->assertStringContainsString('The cleanup after 1 impersonation(s) is not complete yet', $output);
		$this->assertStringContainsString('The session token of 1 of them is not known to be revoked yet', $output);
	}

	public function testEndWithNothingActiveButAPendingCleanupIsNoSuccess(): void {
		$this->reconciler->method('getActive')->willReturn([]);
		$this->reconciler->method('getPending')->willReturn(['bbbbbbbbbbbbbbbb' => self::PENDING['bbbbbbbbbbbbbbbb']]);
		$this->assertSame(Active::EXIT_PENDING, $this->tester->execute(['--end' => true]));
		$this->assertStringContainsString('No active impersonations.', $this->tester->getDisplay());
		$this->assertStringNotContainsString('not known to be revoked', $this->tester->getDisplay());
	}

	public function testEndThatDoesNotEndEverythingFails(): void {
		// e.g. a user that can not be loaded: its impersonation is not ended
		$this->reconciler->method('getActive')->willReturnOnConsecutiveCalls(self::ACTIVE, ['a' => self::ACTIVE['a']]);
		$this->reconciler->method('run')->willReturnOnConsecutiveCalls(0, 1);
		$this->assertSame(Active::EXIT_ACTIVE, $this->tester->execute(['--end' => true]));
		$this->assertStringContainsString('1 impersonation(s) could not be ended:', $this->tester->getDisplay());
	}

	public function testAnImpersonationThatStartedMeanwhileIsNoSuccess(): void {
		// none was listed, but one is active by the time the command has finished
		$this->reconciler->method('getActive')->willReturnOnConsecutiveCalls([], ['b' => self::ACTIVE['b']]);
		$this->assertSame(Active::EXIT_ACTIVE, $this->tester->execute(['--end' => true]));
		$this->assertStringContainsString('carol impersonates bob since', $this->tester->getDisplay());
	}

	public function testBlockComesBeforeTheEnd(): void {
		$this->reconciler->method('getActive')->willReturnOnConsecutiveCalls(self::ACTIVE, []);
		$this->reconciler->method('run')->willReturnCallback(function (bool $endAll = false) {
			$this->calls[] = $endAll ? 'end' : 'run';
			return $endAll ? 2 : 0;
		});
		$this->assertSame(0, $this->tester->execute(['--end' => true, '--block' => true]));
		$this->assertSame(['block', 'run', 'end'], $this->calls);
		$output = $this->tester->getDisplay();
		$this->assertStringContainsString('New impersonations are blocked until occ impersonate:active --unblock.', $output);
		$this->assertStringNotContainsString('can still be started', $output);
	}

	public function testUnblock(): void {
		$this->blocked = true;
		$this->reconciler->method('getActive')->willReturn([]);
		$this->assertSame(0, $this->tester->execute(['--unblock' => true]));
		$this->assertSame(['unblock'], $this->calls);
		$this->assertStringContainsString('New impersonations are allowed again.', $this->tester->getDisplay());
	}

	public function testListSaysThatStartsAreBlocked(): void {
		$this->blocked = true;
		$this->reconciler->method('getActive')->willReturn([]);
		$this->assertSame(0, $this->tester->execute([]));
		$this->assertStringContainsString('New impersonations are blocked (occ impersonate:active --unblock).', $this->tester->getDisplay());
	}

	public function testBlockAndUnblockTogetherDoNothing(): void {
		$this->reconciler->expects($this->never())->method('run');
		$this->reconciler->expects($this->never())->method('blockStarts');
		$this->assertSame(Active::EXIT_INVALID, $this->tester->execute(['--block' => true, '--unblock' => true]));
	}

	public function testWarningWhenTheAppIsNotEnabledForEverybody(): void {
		$this->enabled = '["admin"]';
		$this->reconciler->method('getActive')->willReturn([]);
		$this->assertSame(0, $this->tester->execute([]));
		$this->assertStringContainsString('Warning: the app is not enabled for everybody ("enabled" is "[\\"admin\\"]")', $this->tester->getDisplay());
	}
}
