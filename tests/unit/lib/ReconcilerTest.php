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

use OCA\Impersonate\ActiveImpersonations;
use OCA\Impersonate\AuditTrail;
use OCA\Impersonate\CredentialCleanup;
use OCA\Impersonate\Policy;
use OCA\Impersonate\Reconciler;
use OCP\ILogger;
use OCP\IUser;
use OCP\IUserManager;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

class ReconcilerTest extends TestCase {
	private const START = 1700000000;
	private const RECORD = [
		'impersonator' => 'admin',
		'target' => 'alice',
		'token' => 60,
		'signingKey' => false,
		'start' => self::START,
	];
	private const DONE = ['tokens' => true, 'signingKey' => true, 'ceiling' => 70];

	/** @var ActiveImpersonations|MockObject */
	private $registry;
	/** @var CredentialCleanup|MockObject */
	private $cleanup;
	/** @var Policy|MockObject */
	private $policy;
	/** @var IUserManager|MockObject */
	private $userManager;
	/** @var AuditTrail|MockObject */
	private $auditTrail;
	/** @var ILogger|MockObject */
	private $logger;
	/** @var Reconciler */
	private $reconciler;
	/** @var array<string, array|null> the records as the database has them */
	private $records = [];
	/** @var string[] */
	private $closed = [];
	/** @var array[] [id, now, ceiling, signing key done] */
	private $pending = [];
	/** @var IUser|MockObject */
	private $alice;
	/** @var IUser|null what the user manager answers for "alice" */
	private $loadedAlice;

	protected function setUp(): void {
		parent::setUp();
		$this->registry = $this->createMock(ActiveImpersonations::class);
		// what this process read when it started is not what counts: see testTheRecordsAreReadFromTheDatabase
		$this->registry->method('allFresh')->willReturnCallback(function () {
			return $this->records;
		});
		$this->registry->method('all')->willReturnCallback(function () {
			return $this->records;
		});
		$this->registry->method('close')->willReturnCallback(function ($id) {
			$this->closed[] = $id;
			unset($this->records[$id]);
		});
		$this->registry->method('discard')->willReturnCallback(function ($id) {
			$this->closed[] = $id;
			unset($this->records[$id]);
		});
		$this->registry->method('markPending')->willReturnCallback(function ($id, $record, $now, $ceiling = null, $signingKeyDone = false) {
			// the record the job read from the database is the one that is written back
			$this->assertSame($this->records[$id], $record);
			$this->pending[] = [$id, $now, $ceiling, $signingKeyDone];
			$this->records[$id]['pending'] = true;
			$this->records[$id]['ended'] = $this->records[$id]['ended'] ?? $now;
			if ($ceiling !== null) {
				$this->records[$id]['ceiling'] = $this->records[$id]['ceiling'] ?? $ceiling;
			}
			if ($signingKeyDone) {
				$this->records[$id]['signingKey'] = true;
			}
		});
		$this->cleanup = $this->createMock(CredentialCleanup::class);
		$this->policy = $this->createMock(Policy::class);
		$this->policy->method('getMaxDuration')->willReturn(3600);
		$this->alice = $this->createMock(IUser::class);
		$this->alice->method('getUID')->willReturn('alice');
		$this->loadedAlice = $this->alice;
		$this->userManager = $this->createMock(IUserManager::class);
		$this->userManager->method('get')->willReturnCallback(function ($uid) {
			return $uid === 'alice' ? $this->loadedAlice : null;
		});
		$this->auditTrail = $this->createMock(AuditTrail::class);
		$this->logger = $this->createMock(ILogger::class);
		$this->reconciler = new Reconciler(
			$this->registry,
			$this->cleanup,
			$this->policy,
			$this->userManager,
			$this->auditTrail,
			$this->logger
		);
	}

	public function testNothingToDo(): void {
		$this->cleanup->expects($this->never())->method('run');
		$this->assertSame(0, $this->reconciler->run());
		$this->assertSame(0, $this->reconciler->countPending());
	}

	public function testAnImpersonationThatIsInUseIsLeftAlone(): void {
		$this->records = ['a' => self::RECORD];
		$this->cleanup->method('hasSessionToken')->with($this->alice, 60)->willReturn(true);
		$this->cleanup->expects($this->never())->method('run');
		$this->cleanup->expects($this->never())->method('revokeSessionToken');
		$this->auditTrail->expects($this->never())->method('ended');

		$this->assertSame(0, $this->reconciler->run(false, self::START + 3600 + Reconciler::GRACE));
		$this->assertSame(['a' => self::RECORD], $this->records);
		$this->assertSame(['a' => self::RECORD], $this->reconciler->getActive());
	}

	public function testAnImpersonationWhoseSessionIsGoneGetsTheCleanupAndIsReportedAsEnded(): void {
		// the session expired: the logout that normally runs the cleanup never happened
		$this->records = ['a' => self::RECORD];
		$this->cleanup->method('hasSessionToken')->willReturn(false);
		$this->cleanup->method('revokeSessionToken')->willReturn(true);
		// tokens above the id of the session token appeared during the impersonation
		$this->cleanup->expects($this->once())->method('run')->with($this->alice, 60, false, 'admin', null)->willReturn(self::DONE);
		$this->auditTrail->expects($this->once())->method('ended')->with('admin', 'alice', Reconciler::REASON_SESSION_GONE);
		$this->logger->expects($this->once())->method('warning')->with(
			$this->stringContains('ended without a logout'),
			$this->callback(function (array $context) {
				return $context['target'] === 'alice' && $context['impersonator'] === 'admin'
					&& $context['reason'] === Reconciler::REASON_SESSION_GONE;
			})
		);

		$this->assertSame(1, $this->reconciler->run(false, self::START + 60));
		$this->assertSame(['a'], $this->closed);
		// the next run finds nothing
		$this->assertSame(0, $this->reconciler->run(false, self::START + 120));
	}

	public function testTheRecordsAreReadFromTheDatabase(): void {
		// A cron run that started before the impersonator logged out still has the record in
		// the app config values it read: the database has not, and that is what counts.
		$registry = $this->createMock(ActiveImpersonations::class);
		$registry->method('all')->willReturn(['a' => self::RECORD]);
		$registry->method('allFresh')->willReturn([]);
		$reconciler = new Reconciler($registry, $this->cleanup, $this->policy, $this->userManager, $this->auditTrail, $this->logger);
		$this->cleanup->expects($this->never())->method('hasSessionToken');
		$this->cleanup->expects($this->never())->method('run');
		$this->auditTrail->expects($this->never())->method('ended');
		$this->assertSame(0, $reconciler->run(false, self::START + 60));
		$this->assertSame(0, $reconciler->countPending());
	}

	public function testAnUnusedImpersonationPastTheMaximumDurationIsEnded(): void {
		$this->records = ['a' => self::RECORD];
		$this->cleanup->method('hasSessionToken')->willReturn(true);
		// its session is revoked, so it can not be resumed
		$this->cleanup->expects($this->once())->method('revokeSessionToken')->with($this->alice, 60)->willReturn(true);
		$this->cleanup->expects($this->once())->method('run')->willReturn(self::DONE);
		$this->auditTrail->expects($this->once())->method('ended')->with('admin', 'alice', Reconciler::REASON_MAX_DURATION);

		$this->assertSame(0, $this->reconciler->run(false, self::START + 3600 + Reconciler::GRACE), 'not before the grace period is over');
		$this->assertSame(1, $this->reconciler->run(false, self::START + 3600 + Reconciler::GRACE + 1));
		$this->assertSame(['a'], $this->closed);
	}

	public function testWithoutAMaximumDurationOnlyTheSessionCounts(): void {
		$policy = $this->createMock(Policy::class);
		$policy->method('getMaxDuration')->willReturn(0);
		$reconciler = new Reconciler($this->registry, $this->cleanup, $policy, $this->userManager, $this->auditTrail, $this->logger);
		$this->records = ['a' => self::RECORD];
		$this->cleanup->method('hasSessionToken')->willReturn(true);
		$this->cleanup->expects($this->never())->method('run');
		$this->assertSame(0, $reconciler->run(false, self::START + 10 ** 8));
	}

	public function testTheCleanupOfOneImpersonationKeepsTheSessionsOfTheOthers(): void {
		// alice is impersonated a second time while the first impersonation still waits for its end
		$this->records = ['a' => self::RECORD, 'b' => ['token' => 75] + self::RECORD];
		$this->cleanup->method('hasSessionToken')->willReturnCallback(function ($user, $tokenId) {
			return $tokenId === 75;
		});
		$this->cleanup->method('revokeSessionToken')->willReturn(true);
		$this->cleanup->expects($this->once())->method('run')
			->with($this->alice, 60, false, 'admin', null, [75])->willReturn(self::DONE);
		$this->assertSame(1, $this->reconciler->run(false, self::START + 60));
		$this->assertSame(['a'], $this->closed);
	}

	public function testEndAll(): void {
		$this->records = ['a' => self::RECORD, 'b' => ['impersonator' => 'carol', 'token' => 61] + self::RECORD];
		$this->cleanup->method('hasSessionToken')->willReturn(true);
		$this->cleanup->expects($this->exactly(2))->method('revokeSessionToken')->willReturn(true);
		$this->cleanup->expects($this->exactly(2))->method('run')->willReturn(self::DONE);
		$this->auditTrail->expects($this->exactly(2))->method('ended')->withConsecutive(
			['admin', 'alice', Reconciler::REASON_ADMINISTRATOR],
			['carol', 'alice', Reconciler::REASON_ADMINISTRATOR]
		);

		$this->assertSame(2, $this->reconciler->run(true, self::START + 60));
		$this->assertSame([], $this->records);
	}

	public function testAUserThatCanNotBeLoadedDoesNotCloseTheRecordWhileItsSessionMayBeAlive(): void {
		// deleted - or its backend does not answer: then the session is alive and nothing can be revoked
		$this->records = ['a' => self::RECORD];
		$this->loadedAlice = null;
		$this->cleanup->expects($this->never())->method('run');
		$this->auditTrail->expects($this->never())->method('ended');

		$this->assertSame(0, $this->reconciler->run(false, self::START + 60));
		$this->assertSame(0, $this->reconciler->run(true, self::START + 60), 'not even when asked to end everything');
		$this->assertSame([], $this->closed);
		$this->assertSame(['a' => self::RECORD], $this->records);
	}

	public function testTheImpersonatedUserWasDeletedOrIsUnavailable(): void {
		$this->records = ['a' => self::RECORD];
		$this->loadedAlice = null;
		// Past the maximum duration no session of it is served anymore: it is reported as
		// ended. Its token can not be revoked without the user, so the record still names it.
		$this->cleanup->expects($this->never())->method('run');
		$this->auditTrail->expects($this->once())->method('ended')->with('admin', 'alice', Reconciler::REASON_TARGET_GONE);
		$this->assertSame(1, $this->reconciler->run(false, self::START + 3600 + Reconciler::GRACE + 1));
		$this->assertSame([], $this->closed);
		$this->assertSame([['a', self::START + 3600 + Reconciler::GRACE + 1, null, false]], $this->pending);
	}

	public function testEndingOneImpersonationAtOnce(): void {
		// used when its session token was presented outside its session
		$this->records = ['a' => self::RECORD];
		$this->cleanup->expects($this->once())->method('revokeSessionToken')->with($this->alice, 60)->willReturn(true);
		$this->cleanup->expects($this->once())->method('run')->willReturn(self::DONE);
		$this->auditTrail->expects($this->once())->method('ended')->with('admin', 'alice', Reconciler::REASON_TOKEN_MISUSE);
		$this->reconciler->end('a', self::RECORD, Reconciler::REASON_TOKEN_MISUSE, self::START + 60);
		$this->assertSame(['a'], $this->closed);
	}

	public function testEndingAnImpersonationWhoseUserCanNotBeLoadedKeepsTheRecord(): void {
		// its token may still be valid: the record keeps it known until it could be revoked
		$this->records = ['a' => self::RECORD];
		$this->loadedAlice = null;
		$this->auditTrail->expects($this->once())->method('ended');
		$this->reconciler->end('a', self::RECORD, Reconciler::REASON_TOKEN_MISUSE, self::START + 60);
		$this->assertSame([], $this->closed);
		$this->assertSame([['a', self::START + 60, null, false]], $this->pending);

		// the user is back: the retry revokes the token, nothing is reported twice
		$this->loadedAlice = $this->alice;
		$this->cleanup->expects($this->once())->method('revokeSessionToken')->with($this->alice, 60)->willReturn(true);
		$this->cleanup->method('run')->willReturn(self::DONE);
		$this->assertSame(0, $this->reconciler->run(false, self::START + 400));
		$this->assertSame(['a'], $this->closed);
	}

	public function testEndingARecordThatHasEndedOnlyRetriesItsCleanup(): void {
		$record = self::RECORD + ['pending' => true, 'ended' => self::START + 60];
		$this->records = ['a' => $record];
		$this->cleanup->expects($this->once())->method('revokeSessionToken')->willReturn(true);
		$this->cleanup->method('run')->willReturn(self::DONE);
		$this->auditTrail->expects($this->never())->method('ended');
		$this->reconciler->end('a', $record, Reconciler::REASON_TOKEN_MISUSE, self::START + 90);
		$this->assertSame(['a'], $this->closed);
	}

	public function testAFailedCleanupKeepsTheRecordAndIsRetriedWithoutASecondReport(): void {
		$this->records = ['a' => self::RECORD];
		$this->cleanup->method('hasSessionToken')->willReturn(false);
		$this->cleanup->method('revokeSessionToken')->willReturn(true);
		$calls = [];
		$this->cleanup->method('run')->willReturnCallback(function ($target, $watermark, $signingKeyExisted, $impersonator, $ceiling) use (&$calls) {
			$calls[] = [$watermark, $signingKeyExisted, $ceiling];
			// the signing key is dealt with at once, a token can not be revoked twice in a row
			return ['tokens' => \count($calls) > 2, 'signingKey' => true, 'ceiling' => $ceiling ?? 70];
		});
		$this->auditTrail->expects($this->once())->method('ended');

		$this->assertSame(1, $this->reconciler->run(false, self::START + 60));
		$this->assertSame([['a', self::START + 60, 70, true]], $this->pending);
		$this->assertSame([], $this->closed);
		$this->assertSame([], $this->reconciler->getActive(), 'it has ended, only the cleanup is left');
		$this->assertSame(1, $this->reconciler->countPending());

		$this->assertSame(0, $this->reconciler->run(false, self::START + 400));
		$this->assertSame([], $this->closed);
		$this->assertSame(0, $this->reconciler->run(false, self::START + 800));
		$this->assertSame(['a'], $this->closed);
		// The retries stay within what appeared during the impersonation: they keep the
		// ceiling of the first listing and do not look at the signing key again.
		$this->assertSame([[60, false, null], [60, true, 70], [60, true, 70]], $calls);
	}

	public function testNoCeilingIsRecordedWhileTheSessionTokenIsNotKnownToBeRevoked(): void {
		// the session may still be acting: what appears later can still be its doing
		$this->records = ['a' => self::RECORD];
		$this->cleanup->method('hasSessionToken')->willReturn(true);
		$this->cleanup->method('revokeSessionToken')->willReturnOnConsecutiveCalls(false, true);
		$calls = [];
		$this->cleanup->method('run')->willReturnCallback(function ($target, $watermark, $signingKeyExisted, $impersonator, $ceiling) use (&$calls) {
			$calls[] = $ceiling;
			return ['tokens' => true, 'signingKey' => true, 'ceiling' => $ceiling ?? 70 + \count($calls)];
		});
		$this->assertSame(1, $this->reconciler->run(true, self::START + 60));
		$this->assertSame([['a', self::START + 60, null, true]], $this->pending);
		$this->assertSame(0, $this->reconciler->run(false, self::START + 400));
		$this->assertSame(['a'], $this->closed);
		$this->assertSame([null, null], $calls, 'the retry looks at everything up to now again');
	}

	public function testACleanupThatKeepsFailingIsGivenUpWithAnErrorAWeekAfterTheEnd(): void {
		$ended = self::START + 30 * 24 * 3600;
		$this->records = ['a' => self::RECORD + ['pending' => true, 'ended' => $ended]];
		$this->cleanup->method('revokeSessionToken')->willReturn(false);
		$this->cleanup->method('run')->willReturn(self::DONE);
		$this->auditTrail->expects($this->never())->method('ended');

		$this->logger->expects($this->once())->method('error')->with($this->stringContains('Giving up'));
		$this->assertSame(0, $this->reconciler->run(false, $ended + Reconciler::GIVE_UP_AFTER));
		$this->assertSame([], $this->closed);
		$this->assertSame(0, $this->reconciler->run(false, $ended + Reconciler::GIVE_UP_AFTER + 1));
		$this->assertSame(['a'], $this->closed);
	}

	public function testThePendingCleanupOfADeletedUserIsDropped(): void {
		$this->records = ['a' => self::RECORD + ['pending' => true, 'ended' => self::START + 60]];
		$this->loadedAlice = null;
		$this->cleanup->expects($this->never())->method('run');
		$this->logger->expects($this->never())->method('error');
		$this->assertSame(0, $this->reconciler->run(false, self::START + 3600));
		$this->assertSame([], $this->closed, 'the user may only be unavailable');
		$this->logger->expects($this->once())->method('warning')->with($this->stringContains('the user does not exist'));
		$this->assertSame(0, $this->reconciler->run(false, self::START + 60 + Reconciler::GIVE_UP_AFTER + 1));
		$this->assertSame(['a'], $this->closed);
	}

	public function testAnUnreadableRecordIsRemoved(): void {
		$this->records = ['broken' => null];
		$this->logger->expects($this->once())->method('warning');
		$this->auditTrail->expects($this->never())->method('ended');
		$this->assertSame(0, $this->reconciler->run());
		$this->assertSame(['broken'], $this->closed);
	}

	public function testOneRecordThatCanNotBeHandledDoesNotStopTheOthers(): void {
		$this->records = ['a' => self::RECORD, 'b' => ['token' => 61] + self::RECORD];
		$this->cleanup->method('hasSessionToken')->willReturnCallback(function ($user, $tokenId) {
			if ($tokenId === 60) {
				throw new \RuntimeException('token backend down');
			}
			return false;
		});
		$this->cleanup->method('revokeSessionToken')->willReturn(true);
		$this->cleanup->method('run')->willReturn(self::DONE);
		$this->logger->expects($this->once())->method('logException');

		$this->assertSame(1, $this->reconciler->run(false, self::START + 60));
		$this->assertSame(['b'], $this->closed);
		$this->assertArrayHasKey('a', $this->records, 'tried again by the next run');
	}

	public function testReleaseJobIfIdle(): void {
		$this->registry->expects($this->once())->method('releaseReconcileJobIfIdle');
		$this->reconciler->releaseJobIfIdle();
	}
}
