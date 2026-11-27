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
use OCA\Impersonate\BackgroundJob\Reconcile;
use OCP\BackgroundJob\IJobList;
use OCP\DB\QueryBuilder\IExpressionBuilder;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IConfig;
use OCP\IDBConnection;
use OCP\ILogger;
use OCP\Security\ISecureRandom;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

class ActiveImpersonationsTest extends TestCase {
	private const RECORD = [
		'impersonator' => 'admin',
		'target' => 'alice',
		'token' => 12,
		'signingKey' => false,
		'start' => 1700000000,
	];

	/** @var array<string, string> */
	private $appValues = [];
	/** @var IJobList|MockObject */
	private $jobList;
	/** @var ILogger|MockObject */
	private $logger;
	/** @var ActiveImpersonations */
	private $registry;
	/** @var int */
	private $ids = 0;
	/** @var IDBConnection|MockObject */
	private $connection;
	/** @var array[] rows the database answers the next queries with */
	private $rows = [];

	protected function setUp(): void {
		parent::setUp();
		$config = $this->createMock(IConfig::class);
		$config->method('getAppValue')->willReturnCallback(function ($app, $key, $default = '') {
			return $this->appValues[$key] ?? $default;
		});
		$config->method('setAppValue')->willReturnCallback(function ($app, $key, $value) {
			$this->assertSame('impersonate', $app);
			$this->appValues[$key] = $value;
		});
		$config->method('deleteAppValue')->willReturnCallback(function ($app, $key) {
			unset($this->appValues[$key]);
		});
		$config->method('getAppKeys')->willReturnCallback(function () {
			return \array_keys($this->appValues);
		});
		$secureRandom = $this->createMock(ISecureRandom::class);
		$secureRandom->method('generate')->willReturnCallback(function ($length) {
			return \str_pad('id' . ++$this->ids, $length, '0');
		});
		$this->jobList = $this->createMock(IJobList::class);
		$this->logger = $this->createMock(ILogger::class);
		// the query allFresh() sends; what it asks for is checked against a real database in
		// the HTTP end-to-end tests
		$query = $this->createMock(IQueryBuilder::class);
		foreach (['select', 'addSelect', 'from', 'where'] as $method) {
			$query->method($method)->willReturnSelf();
		}
		$query->method('expr')->willReturn($this->createMock(IExpressionBuilder::class));
		$query->method('execute')->willReturnCallback(function () {
			$rows = $this->rows;
			return new class($rows) {
				/** @var array */
				private $rows;

				public function __construct(array $rows) {
					$this->rows = $rows;
				}

				public function fetchAllAssociative(): array {
					return $this->rows;
				}

				public function free(): void {
				}
			};
		});
		$this->connection = $this->createMock(IDBConnection::class);
		$this->connection->method('getQueryBuilder')->willReturn($query);
		$this->registry = new ActiveImpersonations($config, $secureRandom, $this->jobList, $this->connection, $this->logger);
	}

	public function testOpenGetClose(): void {
		$id = $this->registry->open(self::RECORD);
		$this->assertSame('id10000000000000', $id);
		$this->assertSame(['active_id10000000000000'], \array_keys($this->appValues));
		$this->assertSame(self::RECORD, $this->registry->get($id));
		$this->assertSame([$id => self::RECORD], $this->registry->all());
		$this->registry->close($id);
		$this->assertNull($this->registry->get($id));
		$this->assertSame([], $this->appValues);
	}

	public function testTheRecordHoldsNothingButTheKnownFields(): void {
		$id = $this->registry->open(self::RECORD + ['secret' => 'must not be stored', 'pending' => 'yes']);
		$this->assertSame(self::RECORD, $this->registry->get($id));
		$this->assertStringNotContainsString('secret', $this->appValues['active_' . $id]);
	}

	public static function incompleteProvider(): array {
		return [
			'no impersonator' => [['impersonator' => '']],
			'no target' => [['target' => null]],
			'token id is not a number' => [['token' => '12']],
			'negative token id' => [['token' => -1]],
			'already ended' => [['pending' => true]],
			'signing key state unknown' => [['signingKey' => null]],
			'no start' => [['start' => null]],
		];
	}

	/**
	 * @dataProvider incompleteProvider
	 */
	public function testAnIncompleteRecordIsNotOpened(array $change): void {
		$this->expectException(\InvalidArgumentException::class);
		try {
			$this->registry->open(\array_merge(self::RECORD, $change));
		} finally {
			$this->assertSame([], $this->appValues);
		}
	}

	public function testOpenRegistersTheReconcileJobOnce(): void {
		$this->jobList->method('has')->with(Reconcile::class, null)->willReturnOnConsecutiveCalls(false, true);
		$this->jobList->expects($this->once())->method('add')->with(Reconcile::class);
		$this->registry->open(self::RECORD);
		$this->registry->open(self::RECORD);
		$this->assertCount(2, $this->registry->all());
	}

	public function testAJobThatCanNotBeRegisteredDoesNotStopTheImpersonation(): void {
		$this->jobList->method('has')->willThrowException(new \RuntimeException('job list down'));
		$this->logger->expects($this->once())->method('logException');
		$id = $this->registry->open(self::RECORD);
		$this->assertNotNull($this->registry->get($id));
	}

	public function testMarkPending(): void {
		$id = $this->registry->open(self::RECORD);
		$this->registry->markPending($id, self::RECORD, 1700000100);
		$pending = self::RECORD + ['pending' => true, 'ended' => 1700000100];
		$this->assertSame($pending, $this->registry->get($id));
		// what a later attempt learns is added, the end and the ceiling stay
		$this->registry->markPending($id, $pending, 1700000200, 40);
		$pending['ceiling'] = 40;
		$this->assertSame($pending, $this->registry->get($id));
		$this->registry->markPending($id, $pending, 1700000300, 99, true);
		$this->assertSame(
			\array_merge(self::RECORD, ['signingKey' => true, 'pending' => true, 'ended' => 1700000100, 'ceiling' => 40]),
			$this->registry->get($id)
		);
	}

	public function testMarkPendingWritesTheRecordItIsGiven(): void {
		// the reconcile job reads the records from the database: this process may not have them
		$this->registry->markPending('abcdefgh12345678', self::RECORD + ['secret' => 'x'], 1700000100, 40);
		$this->assertSame(
			self::RECORD + ['pending' => true, 'ended' => 1700000100, 'ceiling' => 40],
			$this->registry->get('abcdefgh12345678')
		);
		// nothing is written for what is no record or no record id
		$this->registry->markPending('../enabled', self::RECORD, 1700000100);
		$this->registry->markPending('abcdefgh12345679', ['target' => 'alice'], 1700000100);
		$this->assertSame(['active_abcdefgh12345678'], \array_keys($this->appValues));
	}

	public function testTheLengthOfTheSessionIdIsKeptIfItIsOne(): void {
		$id = $this->registry->open(self::RECORD + ['sid' => 26]);
		$this->assertSame(self::RECORD + ['sid' => 26], $this->registry->get($id));
		foreach ([0, 9, 4096, '26', null] as $noLength) {
			$id = $this->registry->open(self::RECORD + ['sid' => $noLength]);
			$this->assertSame(self::RECORD, $this->registry->get($id));
		}
	}

	public function testTokenIds(): void {
		$this->assertSame([12, 13], ActiveImpersonations::tokenIds(['a' => self::RECORD, 'b' => null, 'c' => ['token' => 13] + self::RECORD]));
		$this->assertSame([], ActiveImpersonations::tokenIds([]));
	}

	public function testAllFreshReadsTheDatabaseNotTheValuesThisProcessHas(): void {
		$id = $this->registry->open(self::RECORD);
		$changed = \json_encode(self::RECORD + ['pending' => true, 'ended' => 1700000100]);
		// meanwhile another process marked the record pending, a second one appeared, a third is unreadable
		$this->rows = [
			['configkey' => 'active_' . $id, 'configvalue' => $changed],
			['configkey' => 'active_abcdefgh12345678', 'configvalue' => \json_encode(['target' => 'bob'] + self::RECORD)],
			['configkey' => 'active_broken0000000000', 'configvalue' => 'no json'],
			['configkey' => 'active_../x', 'configvalue' => \json_encode(self::RECORD)],
			['configkey' => 'enabled', 'configvalue' => 'yes'],
		];
		$fresh = $this->registry->allFresh();
		$this->assertSame(self::RECORD + ['pending' => true, 'ended' => 1700000100], $fresh[$id]);
		$this->assertSame('bob', $fresh['abcdefgh12345678']['target']);
		$this->assertNull($fresh['broken0000000000']);
		$this->assertNull($fresh['../x']);
		$this->assertCount(4, $fresh);
		// the app config values this process read still say otherwise
		$this->assertSame(self::RECORD, $this->registry->get($id));
		$this->assertCount(1, $this->registry->all());
	}

	public function testTheReconcileJobIsReleasedOnlyWhenNoRecordIsLeft(): void {
		$id = $this->registry->open(self::RECORD);
		$this->jobList->expects($this->once())->method('remove')->with(Reconcile::class);
		// what the database has counts: an impersonation may have started in another process
		$this->rows = [['configkey' => 'active_' . $id, 'configvalue' => \json_encode(self::RECORD)]];
		$this->registry->releaseReconcileJobIfIdle();
		// a cleanup that is to be retried needs the job
		$this->rows = [['configkey' => 'active_' . $id, 'configvalue' => \json_encode(self::RECORD + ['pending' => true, 'ended' => 1700000100])]];
		$this->registry->releaseReconcileJobIfIdle();
		$this->rows = [];
		$this->registry->releaseReconcileJobIfIdle();
	}

	public function testAJobThatCanNotBeReleasedIsOnlyLogged(): void {
		$this->jobList->method('remove')->willThrowException(new \RuntimeException('job list down'));
		$this->logger->expects($this->once())->method('logException');
		$this->registry->releaseReconcileJobIfIdle();
	}

	public function testUnreadableRecordsAreReportedAsSuchAndCanBeDiscarded(): void {
		$id = $this->registry->open(self::RECORD);
		$this->appValues['active_broken0000000000'] = '{"impersonator":"admin"}';
		$this->appValues['active_garbage000000000'] = 'no json';
		$this->appValues['active_../../etc'] = \json_encode(self::RECORD);
		// other settings of the app are no records
		$this->appValues['impersonate_include_groups_list'] = '[]';
		$this->appValues['enabled'] = 'yes';

		$all = $this->registry->all();
		$this->assertSame(self::RECORD, $all[$id]);
		$this->assertNull($all['broken0000000000']);
		$this->assertNull($all['garbage000000000']);
		$this->assertNull($all['../../etc'], 'a key that is no record id is never read as a record');
		$this->assertCount(4, $all);
		$this->assertNull($this->registry->get('../../etc'));

		foreach (\array_keys($all) as $key) {
			if ($all[$key] === null) {
				$this->registry->discard((string)$key);
			}
		}
		$this->assertSame(
			['active_' . $id, 'impersonate_include_groups_list', 'enabled'],
			\array_keys($this->appValues)
		);
	}

	public function testCloseIgnoresWhatIsNoRecordId(): void {
		$this->appValues['enabled'] = 'yes';
		$this->registry->close('');
		$this->registry->close('../enabled');
		$this->assertSame(['enabled' => 'yes'], $this->appValues);
	}
}
