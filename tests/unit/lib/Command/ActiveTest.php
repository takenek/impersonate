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

	protected function setUp(): void {
		parent::setUp();
		$this->reconciler = $this->createMock(Reconciler::class);
		$this->tester = new CommandTester(new Active($this->reconciler));
	}

	public function testNoActiveImpersonations(): void {
		$this->reconciler->method('getActive')->willReturn([]);
		// what is over anyway is finished first, nothing is ended by force
		$this->reconciler->expects($this->once())->method('run')->with(false);
		// listing leaves the background job alone
		$this->reconciler->expects($this->never())->method('releaseJobIfIdle');
		$this->assertSame(0, $this->tester->execute([]));
		$this->assertStringContainsString('No active impersonations', $this->tester->getDisplay());
	}

	public function testEndWithNothingActiveStillReleasesTheBackgroundJob(): void {
		// the last step before the app is disabled: nothing of it stays on the job list
		$this->reconciler->method('getActive')->willReturn([]);
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

	public function testEnd(): void {
		$this->reconciler->method('getActive')->willReturn(self::ACTIVE);
		$this->reconciler->expects($this->exactly(2))->method('run')->withConsecutive([false], [true])
			->willReturnOnConsecutiveCalls(0, 2);
		$this->reconciler->expects($this->once())->method('releaseJobIfIdle');
		$this->assertSame(0, $this->tester->execute(['--end' => true]));
		$this->assertStringContainsString('Ended 2 impersonation(s).', $this->tester->getDisplay());
		$this->assertStringNotContainsString('not complete', $this->tester->getDisplay());
	}

	public function testEndSaysWhenACleanupIsLeftToTheBackgroundJob(): void {
		$this->reconciler->method('getActive')->willReturn(self::ACTIVE);
		$this->reconciler->method('run')->willReturnOnConsecutiveCalls(0, 2);
		$this->reconciler->method('countPending')->willReturn(1);
		$this->assertSame(0, $this->tester->execute(['--end' => true]));
		$this->assertStringContainsString('The cleanup after 1 impersonation(s) is not complete yet', $this->tester->getDisplay());
	}

	public function testEndThatDoesNotEndEverythingFails(): void {
		$this->reconciler->method('getActive')->willReturn(self::ACTIVE);
		$this->reconciler->method('run')->willReturnOnConsecutiveCalls(0, 1);
		$this->assertSame(1, $this->tester->execute(['--end' => true]));
	}
}
