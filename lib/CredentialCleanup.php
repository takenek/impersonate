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

use OC\Authentication\Token\DefaultToken;
use OC\Authentication\Token\DefaultTokenProvider;
use OC\Authentication\Token\IToken;
use OCP\IConfig;
use OCP\ILogger;
use OCP\IUser;

/**
 * What an impersonation leaves behind for the impersonated user is removed
 * when it ends - by the session (Util) or, when the session is gone, by the
 * reconcile job (Reconciler):
 *
 * - the session token of the impersonation itself (by its id, wherever the
 *   session is now);
 * - app passwords created from the impersonated session, and sessions that
 *   were logged in with the session token of the impersonation as their
 *   credential: neither has a stored password, and tokens are numbered in the
 *   order they are created, so tokens of the user without a stored password
 *   and with an id above the id of the session token of the impersonation are
 *   revoked;
 * - a URL signing key (pre-signed WebDAV URLs) if the user had none at the
 *   start.
 *
 * The last two rules do not know who created the credential, so one that the
 * account owner created in that time is removed as well (an app password
 * created from a session without a login password, such a session itself,
 * e.g. after single sign-on). The owner is notified and an event is
 * dispatched for each (AuditTrail::credentialRevoked).
 * Once the tokens could be listed after the end, later tokens are out of reach
 * ("ceiling"), however often the cleanup has to be retried.
 */
class CredentialCleanup {
	/** the platform may not list more tokens of a user than this */
	private const TOKEN_LIST_LIMIT = 1000;
	/** how often the tokens are listed again while a pass still finds something to revoke */
	private const MAX_PASSES = 4;

	/** @var DefaultTokenProvider */
	private $tokenProvider;
	/** @var IConfig */
	private $config;
	/** @var AuditTrail */
	private $auditTrail;
	/** @var ILogger */
	private $logger;

	public function __construct(DefaultTokenProvider $tokenProvider, IConfig $config, AuditTrail $auditTrail, ILogger $logger) {
		$this->tokenProvider = $tokenProvider;
		$this->config = $config;
		$this->auditTrail = $auditTrail;
		$this->logger = $logger;
	}

	public function hasSigningKey(IUser $user): bool {
		return (string)$this->config->getUserValue($user->getUID(), 'core', 'signing-key', '') !== '';
	}

	/**
	 * @param int $watermark tokens of $target with a higher id appeared during the impersonation
	 * @param bool $signingKeyExisted $target had a signing key when the impersonation started
	 *                                (or the key was dealt with by an earlier run)
	 * @param int|null $ceiling tokens with a higher id appeared after the impersonation had ended
	 *                          and are left alone; null: not known yet
	 * @param int[] $keep ids of tokens that are left alone whatever they look like: the session
	 *                    tokens of other impersonations of the same user
	 * @return array{tokens: bool, signingKey: bool, ceiling: int|null} what is done (false: failed,
	 *                          to be retried) and the ceiling for later runs (null: the tokens could
	 *                          not be listed)
	 */
	public function run(IUser $target, int $watermark, bool $signingKeyExisted, ?string $impersonatorUid, ?int $ceiling = null, array $keep = []): array {
		$tokensDone = true;
		try {
			// A session that is revoked here may have created another one meanwhile: the
			// tokens are listed again until a pass finds nothing to revoke.
			for ($pass = 0; $pass < self::MAX_PASSES; $pass++) {
				$tokens = $this->tokenProvider->getTokenByUser($target);
				if ($pass === 0 && \count($tokens) >= self::TOKEN_LIST_LIMIT) {
					$this->logger->error(
						'User "{target}" has so many tokens that the cleanup after the impersonation by "{impersonator}" may not have seen all of them: check the app passwords of that user',
						['app' => 'impersonate', 'target' => $target->getUID(), 'impersonator' => $impersonatorUid]
					);
				}
				$highest = $watermark;
				foreach ($tokens as $token) {
					$highest = \max($highest, (int)$token->getId());
				}
				$limit = $ceiling ?? $highest;
				// First all of them are revoked, then it is told: a session that is to be
				// revoked gets no time to create another one in between.
				$revoked = [];
				foreach ($tokens as $token) {
					$id = (int)$token->getId();
					if (!$token instanceof DefaultToken
						|| $id <= $watermark
						|| $id > $limit
						|| \in_array($id, $keep, true)
						// what comes from the impersonated session or its token has no stored password
						|| (string)$token->getPassword() !== ''
					) {
						continue;
					}
					try {
						$this->tokenProvider->invalidateTokenById($target, $token->getId());
						$revoked[] = $token;
					} catch (\Throwable $e) {
						$this->logger->logException($e, ['app' => 'impersonate']);
						$tokensDone = false;
					}
				}
				foreach ($revoked as $token) {
					$this->announce($target, $token, $impersonatorUid);
				}
				if (!$tokensDone) {
					// What could not be revoked may still create tokens: no ceiling is set (a
					// given one stays), the retry looks at everything again.
					break;
				}
				if ($ceiling !== null || $revoked === []) {
					// a given ceiling does not move; otherwise it is what the last listing showed
					$ceiling = $ceiling ?? $highest;
					break;
				}
			}
			if ($ceiling === null) {
				// a revocation failed, or every pass revoked something: whatever keeps creating
				// tokens is still at it
				$tokensDone = false;
			}
		} catch (\Throwable $e) {
			$this->logger->logException($e, ['app' => 'impersonate']);
			$tokensDone = false;
		}

		$signingKeyDone = true;
		if (!$signingKeyExisted) {
			try {
				if ($this->hasSigningKey($target)) {
					$this->config->deleteUserValue($target->getUID(), 'core', 'signing-key');
					$this->logger->warning(
						'Removed the URL signing key of user "{target}" created while "{impersonator}" impersonated them',
						['app' => 'impersonate', 'target' => $target->getUID(), 'impersonator' => $impersonatorUid]
					);
					$this->auditTrail->credentialRevoked($target->getUID(), 'URL signing key', $impersonatorUid);
				}
			} catch (\Throwable $e) {
				$this->logger->logException($e, ['app' => 'impersonate']);
				$signingKeyDone = false;
			}
		}
		return ['tokens' => $tokensDone, 'signingKey' => $signingKeyDone, 'ceiling' => $ceiling];
	}

	/**
	 * Log, event and notification for a token the cleanup revoked.
	 */
	private function announce(IUser $target, DefaultToken $token, ?string $impersonatorUid): void {
		$isAppPassword = (int)$token->getType() === IToken::PERMANENT_TOKEN;
		$name = (string)$token->getName();
		$this->logger->warning(
			$isAppPassword
				? 'Revoked passwordless app password "{name}" of user "{target}" created during the impersonation by "{impersonator}"'
				: 'Revoked passwordless session "{name}" of user "{target}" created during the impersonation by "{impersonator}"',
			[
				'app' => 'impersonate',
				'name' => $name,
				'target' => $target->getUID(),
				'impersonator' => $impersonatorUid,
			]
		);
		$this->auditTrail->credentialRevoked(
			$target->getUID(),
			$isAppPassword ? $name : 'session ' . $name,
			$impersonatorUid
		);
	}

	/**
	 * Does the user (still) have the session token with this id? Only the id
	 * counts: the name of a token is free text and decides nothing. If the user
	 * has more tokens than the platform lists, a token that is not in the list
	 * counts as present: its absence can not be told.
	 *
	 * @throws \Exception if the tokens can not be read
	 */
	public function hasSessionToken(IUser $user, int $tokenId): bool {
		$tokens = $this->tokenProvider->getTokenByUser($user);
		foreach ($tokens as $token) {
			if ((int)$token->getId() === $tokenId) {
				return true;
			}
		}
		return \count($tokens) >= self::TOKEN_LIST_LIMIT;
	}

	/**
	 * Revoke the session token of an impersonation by its id, which ends that
	 * session wherever it is.
	 *
	 * @return bool false if that failed and has to be retried
	 */
	public function revokeSessionToken(IUser $user, int $tokenId): bool {
		try {
			// no error if there is no such token (anymore)
			$this->tokenProvider->invalidateTokenById($user, $tokenId);
			return true;
		} catch (\Throwable $e) {
			$this->logger->logException($e, ['app' => 'impersonate']);
			return false;
		}
	}

	/**
	 * @return array{id: int, uid: string}|null the token with this secret (e.g. a session id), null if there is none
	 * @throws \Exception if the token can not be looked up
	 */
	public function findToken(string $secret): ?array {
		if ($secret === '') {
			return null;
		}
		try {
			$token = $this->tokenProvider->getToken($secret);
		} catch (\OC\Authentication\Exceptions\InvalidTokenException $e) {
			return null;
		}
		return ['id' => (int)$token->getId(), 'uid' => (string)$token->getUID()];
	}
}
