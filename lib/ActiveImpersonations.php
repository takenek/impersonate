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

namespace OCA\Impersonate;

use OCA\Impersonate\BackgroundJob\Reconcile;
use OCP\BackgroundJob\IJobList;
use OCP\IConfig;
use OCP\IDBConnection;
use OCP\ILogger;
use OCP\Security\ISecureRandom;

/**
 * Server side records of the impersonations that are active.
 *
 * The session alone can not be relied on: it may just expire, lose its
 * marker or be left behind while its token is used elsewhere. Each record
 * says which session token belongs to an impersonation and holds what is
 * needed to finish it without the session (ImpersonationGuard, Reconciler).
 * The records are app config values "active_<id>" (JSON); they hold no
 * secrets.
 *
 * Record: [
 *   'impersonator' => string, 'target' => string,
 *   'token' => int     id of the session token "Impersonated by <uid>"; tokens of the
 *                      target with a higher id appeared during the impersonation,
 *   'signingKey' => bool the target had a URL signing key when it started,
 *   'start' => int     unix time,
 *   'sid' => int       (optional) length of the id of the impersonated session - not the id,
 *   only once the impersonation has ended and its cleanup has to be retried:
 *   'pending' => true,
 *   'ended' => int     unix time,
 *   'ceiling' => int   (optional) tokens with a higher id appeared after the end
 * ]
 */
class ActiveImpersonations {
	private const APP = 'impersonate';
	private const PREFIX = 'active_';

	/** @var IConfig */
	private $config;
	/** @var ISecureRandom */
	private $secureRandom;
	/** @var IJobList */
	private $jobList;
	/** @var IDBConnection */
	private $connection;
	/** @var ILogger */
	private $logger;

	public function __construct(
		IConfig $config,
		ISecureRandom $secureRandom,
		IJobList $jobList,
		IDBConnection $connection,
		ILogger $logger
	) {
		$this->config = $config;
		$this->secureRandom = $secureRandom;
		$this->jobList = $jobList;
		$this->connection = $connection;
		$this->logger = $logger;
	}

	/**
	 * @param array<string, mixed> $record
	 * @return string id of the record
	 * @throws \InvalidArgumentException if the record is not complete
	 */
	public function open(array $record): string {
		$record = self::normalize($record);
		if ($record === null || isset($record['pending'])) {
			throw new \InvalidArgumentException('Incomplete impersonation record');
		}
		$id = $this->secureRandom->generate(16, ISecureRandom::CHAR_LOWER . ISecureRandom::CHAR_DIGITS);
		$this->config->setAppValue(self::APP, self::PREFIX . $id, \json_encode($record, JSON_THROW_ON_ERROR));
		$this->ensureReconcileJob();
		return $id;
	}

	/**
	 * @return array<string, mixed>|null null if there is no (valid) record
	 */
	public function get(string $id): ?array {
		if (!self::isId($id)) {
			return null;
		}
		return self::decode($this->config->getAppValue(self::APP, self::PREFIX . $id, ''));
	}

	/**
	 * The records as the database has them now. The app config values behind
	 * all() are read once per process: a long running process (cron, occ)
	 * would otherwise act on impersonations that ended or changed in the
	 * meantime.
	 *
	 * @return array<string, array<string, mixed>|null> id => record, null for an unreadable record
	 * @throws \Exception if the database can not be read
	 */
	public function allFresh(): array {
		$query = $this->connection->getQueryBuilder();
		// all values of the app (a handful): the records are picked below, without a
		// LIKE whose escaping differs between databases
		$query->select('configkey')
			->addSelect('configvalue')
			->from('appconfig')
			->where($query->expr()->eq('appid', $query->createNamedParameter(self::APP)));
		$result = $query->execute();
		// the names the database layer of the platform has for "all rows" and "release"
		$fetchAll = \method_exists($result, 'fetchAllAssociative') ? 'fetchAllAssociative' : 'fetchAll';
		$rows = $result->$fetchAll();
		foreach (['free', 'closeCursor'] as $release) {
			if (\method_exists($result, $release)) {
				$result->$release();
				break;
			}
		}
		$records = [];
		foreach (\is_array($rows) ? $rows : [] as $row) {
			$key = \is_array($row) ? ($row['configkey'] ?? null) : null;
			if (!\is_string($key) || \strpos($key, self::PREFIX) !== 0) {
				continue;
			}
			$id = \substr($key, \strlen(self::PREFIX));
			$records[$id] = self::isId($id) ? self::decode($row['configvalue'] ?? null) : null;
		}
		return $records;
	}

	/**
	 * The impersonation has ended but its cleanup did not complete: keep the
	 * record so that the reconcile job retries it.
	 *
	 * @param array<string, mixed> $record the record as the caller read it (the reconcile job reads
	 *                                     it from the database, see allFresh())
	 * @param int|null $ceiling highest token id the cleanup may touch (see CredentialCleanup), if known
	 * @param bool $signingKeyDone the URL signing key needs no further attention
	 */
	public function markPending(string $id, array $record, int $now, ?int $ceiling = null, bool $signingKeyDone = false): void {
		$record = self::isId($id) ? self::normalize($record) : null;
		if ($record === null) {
			return;
		}
		$record['pending'] = true;
		$record['ended'] = $record['ended'] ?? $now;
		if ($ceiling !== null && !isset($record['ceiling'])) {
			$record['ceiling'] = $ceiling;
		}
		if ($signingKeyDone) {
			// nothing to remove anymore, whatever the user does from now on
			$record['signingKey'] = true;
		}
		$this->config->setAppValue(self::APP, self::PREFIX . $id, \json_encode($record, JSON_THROW_ON_ERROR));
	}

	public function close(string $id): void {
		if (self::isId($id)) {
			$this->config->deleteAppValue(self::APP, self::PREFIX . $id);
		}
	}

	/**
	 * @param array<string, array<string, mixed>|null> $records as all() or allFresh() returns them
	 * @return int[] ids of the session tokens the records name
	 */
	public static function tokenIds(array $records): array {
		$ids = [];
		foreach ($records as $record) {
			if ($record !== null) {
				$ids[] = $record['token'];
			}
		}
		return $ids;
	}

	/**
	 * @return array<string, array<string, mixed>|null> id => record, null for an unreadable record
	 */
	public function all(): array {
		$records = [];
		foreach ($this->config->getAppKeys(self::APP) as $key) {
			if (!\is_string($key) || \strpos($key, self::PREFIX) !== 0) {
				continue;
			}
			$id = \substr($key, \strlen(self::PREFIX));
			$records[$id] = self::isId($id) ? self::decode($this->config->getAppValue(self::APP, $key, '')) : null;
		}
		return $records;
	}

	/**
	 * Remove a record whatever its key looks like (used for unreadable records).
	 */
	public function discard(string $id): void {
		$this->config->deleteAppValue(self::APP, self::PREFIX . $id);
	}

	/**
	 * Take the reconcile job off the job list when no record is left. The job
	 * list keeps a job of an app that is disabled, which the platform reports
	 * as an error on every run: "occ impersonate:active --end" leaves nothing
	 * behind. The next impersonation registers the job again. Never throws.
	 */
	public function releaseReconcileJobIfIdle(): void {
		try {
			// as the database has it now: an impersonation may have started meanwhile
			if ($this->allFresh() === []) {
				$this->jobList->remove(Reconcile::class);
			}
		} catch (\Throwable $e) {
			$this->logger->logException($e, ['app' => 'impersonate']);
		}
	}

	/**
	 * The records are useless without the job that works on them. A failure to
	 * register it is logged and does not stop the impersonation: the session
	 * based controls do not depend on the job.
	 */
	private function ensureReconcileJob(): void {
		try {
			if (!$this->jobList->has(Reconcile::class, null)) {
				$this->jobList->add(Reconcile::class);
			}
		} catch (\Throwable $e) {
			$this->logger->logException($e, ['app' => 'impersonate']);
		}
	}

	private static function isId(string $id): bool {
		return \preg_match('/^[a-z0-9]{16}\z/', $id) === 1;
	}

	/**
	 * @param mixed $raw
	 * @return array<string, mixed>|null
	 */
	private static function decode($raw): ?array {
		if (!\is_string($raw) || $raw === '') {
			return null;
		}
		$record = \json_decode($raw, true);
		return \is_array($record) ? self::normalize($record) : null;
	}

	/**
	 * @param array<mixed> $record
	 * @return array<string, mixed>|null the record with exactly the known fields, null if one is missing
	 */
	private static function normalize(array $record): ?array {
		foreach (['impersonator', 'target'] as $key) {
			if (!isset($record[$key]) || !\is_string($record[$key]) || $record[$key] === '') {
				return null;
			}
		}
		foreach (['token', 'start'] as $key) {
			if (!isset($record[$key]) || !\is_int($record[$key]) || $record[$key] < 0) {
				return null;
			}
		}
		if (!isset($record['signingKey']) || !\is_bool($record['signingKey'])) {
			return null;
		}
		$normalized = [
			'impersonator' => $record['impersonator'],
			'target' => $record['target'],
			'token' => $record['token'],
			'signingKey' => $record['signingKey'],
			'start' => $record['start'],
		];
		if (isset($record['sid']) && \is_int($record['sid']) && $record['sid'] >= 16 && $record['sid'] <= 256) {
			$normalized['sid'] = $record['sid'];
		}
		if (($record['pending'] ?? false) === true) {
			$normalized['pending'] = true;
			$normalized['ended'] = isset($record['ended']) && \is_int($record['ended']) && $record['ended'] >= 0
				? $record['ended']
				: $record['start'];
			if (isset($record['ceiling']) && \is_int($record['ceiling']) && $record['ceiling'] >= 0) {
				$normalized['ceiling'] = $record['ceiling'];
			}
		}
		return $normalized;
	}
}
