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

use OCP\ILogger;
use OCP\IUser;
use OCP\IUserManager;

/**
 * Finishes impersonations without their session (background job
 * BackgroundJob\Reconcile, occ impersonate:active --end, ImpersonationGuard):
 *
 * - an impersonation whose session expired, was revoked or was lost gets the
 *   same cleanup as one that was logged out, and is reported as ended (the
 *   session based end can not happen anymore);
 * - an impersonation that is past the maximum duration and was not used since
 *   (the guard ends it on its next request) is ended by revoking its session;
 * - an impersonation whose session token is used outside its session is ended
 *   at once (end());
 * - a cleanup that failed when an impersonation ended is retried.
 */
class Reconciler {
	/** seconds past the maximum duration before the job ends an impersonation that the guard has not ended */
	public const GRACE = 120;
	/** seconds after the end of an impersonation after which the retries of a failed cleanup are given up */
	public const GIVE_UP_AFTER = 7 * 24 * 3600;

	public const REASON_TARGET_GONE = 'the impersonated user does not exist anymore or can not be loaded';
	public const REASON_SESSION_GONE = 'the impersonated session expired or was revoked';
	public const REASON_MAX_DURATION = 'the maximum duration of the impersonation was reached';
	public const REASON_ADMINISTRATOR = 'ended by an administrator (occ impersonate:active --end)';
	public const REASON_TOKEN_MISUSE = 'its session token was presented by a request that is not part of the impersonated session';

	/** @var ActiveImpersonations */
	private $registry;
	/** @var CredentialCleanup */
	private $cleanup;
	/** @var Policy */
	private $policy;
	/** @var IUserManager */
	private $userManager;
	/** @var AuditTrail */
	private $auditTrail;
	/** @var ILogger */
	private $logger;

	public function __construct(
		ActiveImpersonations $registry,
		CredentialCleanup $cleanup,
		Policy $policy,
		IUserManager $userManager,
		AuditTrail $auditTrail,
		ILogger $logger
	) {
		$this->registry = $registry;
		$this->cleanup = $cleanup;
		$this->policy = $policy;
		$this->userManager = $userManager;
		$this->auditTrail = $auditTrail;
		$this->logger = $logger;
	}

	/**
	 * @return array<string, array<string, mixed>> id => record of the impersonations that have not ended,
	 *                                             as the database has them now
	 */
	public function getActive(): array {
		$active = [];
		foreach ($this->registry->allFresh() as $id => $record) {
			if ($record !== null && !isset($record['pending'])) {
				$active[(string)$id] = $record;
			}
		}
		return $active;
	}

	/**
	 * @return int number of impersonations that have ended but whose cleanup is still to be retried
	 */
	public function countPending(): int {
		return \count($this->getPending());
	}

	/**
	 * @return int number of impersonations that have ended but whose session token is not known to
	 *             be revoked yet (a part of countPending())
	 */
	public function countPendingWithoutRevokedToken(): int {
		return \count(\array_filter($this->getPending(), [ActiveImpersonations::class, 'namesCredential']));
	}

	/**
	 * Block or allow new impersonations (maintenance window, see ActiveImpersonations).
	 */
	public function blockStarts(bool $blocked): void {
		if ($blocked) {
			$this->registry->blockStarts();
		} else {
			$this->registry->allowStarts();
		}
	}

	public function startsBlocked(): bool {
		return $this->registry->startsBlocked();
	}

	/**
	 * @return array<string, array<string, mixed>> id => record of the impersonations that have ended
	 *                                             but wait for their cleanup, as the database has them now
	 */
	public function getPending(): array {
		$pending = [];
		foreach ($this->registry->allFresh() as $id => $record) {
			if ($record !== null && isset($record['pending'])) {
				$pending[(string)$id] = $record;
			}
		}
		return $pending;
	}

	/**
	 * @param bool $endAll end every active impersonation, not only those that are over
	 * @return int number of impersonations this run ended
	 */
	public function run(bool $endAll = false, ?int $now = null): int {
		$now = $now ?? \time();
		$ended = 0;
		// As the database has them now, not as this process read the app config when it
		// started: a cron run must not act on what a session has ended or changed since.
		$records = $this->registry->allFresh();
		foreach ($records as $id => $record) {
			$id = (string)$id;
			try {
				if ($record === null) {
					// Nothing can be done with it. A session that belongs to it is ended by
					// the guard on its next request (its record is gone).
					$this->logger->warning(
						'Removed the unreadable record "{id}" of an impersonation',
						['app' => 'impersonate', 'id' => $id]
					);
					$this->registry->discard($id);
				} elseif (isset($record['pending'])) {
					$this->retryCleanup($id, $record, $now);
				} elseif ($this->endIfOver($id, $record, $endAll, $now)) {
					$ended++;
				}
			} catch (\Throwable $e) {
				// one record must not keep the others from being handled
				$this->logger->logException($e, ['app' => 'impersonate']);
			}
		}
		return $ended;
	}

	/**
	 * End one impersonation now, whatever state its session is in: its session
	 * token is revoked, the cleanup runs and the end is reported. For a record
	 * that has ended already only the cleanup is retried.
	 *
	 * @param array<string, mixed> $record
	 */
	public function end(string $id, array $record, string $reason, ?int $now = null): void {
		$now = $now ?? \time();
		// As the database has them now: an impersonation that started a moment ago keeps its
		// session, and what is decided below is decided on the record as it is now, not as the
		// caller read it (another request may have ended or changed it in between).
		$records = $this->registry->allFresh();
		$current = $records[$id] ?? null;
		if ($current === null) {
			// Ended and reported elsewhere meanwhile (or unreadable). Its token was presented
			// a moment ago: it is revoked in any case, nothing is reported a second time.
			$target = $this->userManager->get($record['target']);
			if ($target !== null) {
				$this->cleanup->revokeSessionToken($target, $record['token']);
			}
			return;
		}
		if (isset($current['pending'])) {
			$this->retryCleanup($id, $current, $now);
			return;
		}
		$this->finish($id, $current, $this->userManager->get($current['target']), $reason, $now);
	}

	/**
	 * See ActiveImpersonations::releaseReconcileJobIfIdle().
	 */
	public function releaseJobIfIdle(): void {
		$this->registry->releaseReconcileJobIfIdle();
	}

	/**
	 * @param array<string, mixed> $record
	 * @return bool true if the impersonation was ended
	 */
	private function endIfOver(string $id, array $record, bool $endAll, int $now): bool {
		$target = $this->userManager->get($record['target']);
		$max = $this->policy->getMaxDuration();
		$age = $now - $record['start'];
		$pastMaximum = $max > 0 && $age > $max + self::GRACE;
		if ($target === null) {
			// The user was deleted - or its backend does not answer right now. Nothing can
			// be revoked without the user: while a session of the impersonation may be in
			// use the guard deals with it; after that the impersonation is reported as
			// ended and its record waits for the user (see cleanUp()).
			if (!$pastMaximum && $age <= self::GIVE_UP_AFTER) {
				return false;
			}
			$reason = self::REASON_TARGET_GONE;
		} elseif (!$this->cleanup->hasSessionToken($target, $record['token'])) {
			$reason = self::REASON_SESSION_GONE;
		} elseif ($endAll) {
			$reason = self::REASON_ADMINISTRATOR;
		} elseif ($pastMaximum) {
			$reason = self::REASON_MAX_DURATION;
		} else {
			return false;
		}
		$this->finish($id, $record, $target, $reason, $now);
		return true;
	}

	/**
	 * @param array<string, mixed> $record of an impersonation that has not ended yet
	 */
	private function finish(string $id, array $record, ?IUser $target, string $reason, int $now): void {
		$this->cleanUp($id, $record, $target, $now);
		$this->logger->warning(
			'Impersonation of user "{target}" by "{impersonator}" ended without a logout: {reason}',
			[
				'app' => 'impersonate',
				'target' => $record['target'],
				'impersonator' => $record['impersonator'],
				'reason' => $reason,
			]
		);
		$this->auditTrail->ended($record['impersonator'], $record['target'], $reason, $id);
	}

	/**
	 * @param array<string, mixed> $record of an impersonation that has ended and was reported
	 */
	private function retryCleanup(string $id, array $record, int $now): void {
		$target = $this->userManager->get($record['target']);
		$result = $this->cleanUp($id, $record, $target, $now);
		if ($result['closed'] || $now - $record['ended'] <= self::GIVE_UP_AFTER) {
			return;
		}
		if ($target === null) {
			// deleted: its tokens went with it
			$this->logger->warning(
				'Dropping the cleanup after the impersonation of user "{target}" by "{impersonator}": the user does not exist',
				['app' => 'impersonate', 'target' => $record['target'], 'impersonator' => $record['impersonator']]
			);
		} elseif (!$result['tokenRevoked']) {
			// As long as the session token is not known to be revoked the record has to name it
			// (cleanUp()): it is kept, however long that takes.
			$this->logger->error(
				'The session token of the impersonation of user "{target}" by "{impersonator}" could still not be revoked: the record is kept, check the sessions of that user and the ownCloud log',
				['app' => 'impersonate', 'target' => $record['target'], 'impersonator' => $record['impersonator']]
			);
			return;
		} else {
			$this->logger->error(
				'Giving up the cleanup after the impersonation of user "{target}" by "{impersonator}": check the sessions and app passwords of that user',
				['app' => 'impersonate', 'target' => $record['target'], 'impersonator' => $record['impersonator']]
			);
		}
		$this->registry->close($id);
	}

	/**
	 * End the session of the impersonation (if it still exists) and remove the
	 * credentials that appeared during it. The record is closed when everything
	 * is done, otherwise it is kept for a retry: as long as its token is not
	 * known to be revoked, the record has to name it (ImpersonationGuard).
	 *
	 * @param array<string, mixed> $record
	 * @return array{closed: bool, tokenRevoked: bool} whether the record was closed, and whether the
	 *                                                  session token is known to be revoked
	 */
	private function cleanUp(string $id, array $record, ?IUser $target, int $now): array {
		$wasRevoked = ($record['tokenRevoked'] ?? false) === true;
		if ($target === null) {
			// The user was deleted (then its tokens are gone with it) - or its backend does
			// not answer right now (then nothing can be revoked yet). Retried until
			// retryCleanup() gives up.
			if (!isset($record['pending'])) {
				$this->registry->markPending($id, $record, $now);
			}
			return ['closed' => false, 'tokenRevoked' => $wasRevoked];
		}
		$revoked = $this->cleanup->revokeSessionToken($target, $record['token']);
		// Another impersonation of the same user (a later or a parallel one) keeps its session: the
		// records as the database has them right before this cleanup, not when the run started.
		$others = ActiveImpersonations::tokenIds($this->registry->allFresh());
		$result = $this->cleanup->run(
			$target,
			$record['token'],
			$record['signingKey'],
			$record['impersonator'],
			$record['ceiling'] ?? null,
			\array_values(\array_diff($others, [$record['token']]))
		);
		if ($revoked && $result['tokens'] && $result['signingKey']) {
			$this->registry->close($id);
			return ['closed' => true, 'tokenRevoked' => true];
		}
		$this->registry->markPending(
			$id,
			$record,
			$now,
			// Only once the session is known to be over is "what appeared later" none of
			// its doing.
			$revoked ? $result['ceiling'] : null,
			$result['signingKey'],
			$revoked
		);
		return ['closed' => false, 'tokenRevoked' => $revoked || $wasRevoked];
	}
}
