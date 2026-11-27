<?php
/**
 * Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
 * Maintained by Marek Królikowski (TaKeN): https://github.com/takenek/impersonate
 * Modified on 2026-11-26 and 2026-11-27 by Marek Królikowski (TaKeN): ownCloud 11.1 support and
 * security hardening, see CHANGELOG.md. SPDX-License-Identifier: AGPL-3.0-only
 * See LICENSE and COPYRIGHT.
 *
 * Based on the ownCloud "impersonate" app (https://github.com/owncloud/impersonate):
 *
 * @author Sujith Haridasan <sharidasan@owncloud.com>
 * @author Jannik Stehle <jstehle@owncloud.com>
 *
 * @copyright Copyright (c) 2021, ownCloud GmbH
 * @license AGPL-3.0
 *
 * This code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License, version 3,
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

namespace OCA\Impersonate;

use OC\Authentication\Exceptions\InvalidTokenException;
use OC\Authentication\Exceptions\PasswordlessTokenException;
use OC\Authentication\Token\DefaultToken;
use OC\Authentication\Token\DefaultTokenProvider;
use OC\Authentication\Token\IToken;
use OC\Security\CSRF\CsrfTokenManager;
use OC\User\Session;
use OCP\IConfig;
use OCP\ILogger;
use OCP\ISession;
use OCP\IUser;
use OCP\IUserManager;
use OCP\Security\ISecureRandom;

/**
 * Switches the logged in user of the current session between the
 * impersonator and the impersonated user.
 *
 * Security properties:
 * - an impersonation can only be started from an interactive session (a
 *   session that has its own session token), never by a request that is only
 *   authenticated by HTTP Basic credentials or an app password;
 * - session values bound to the impersonator's identity (login name, the
 *   password kept for "log-in credentials, save in session" external
 *   storages, app password and DAV markers) are removed from the session
 *   while impersonating and restored afterwards;
 * - the session id and the CSRF token are rotated on every switch;
 * - the impersonator's own session token (including the stored login
 *   password, if it has one) is parked under a random secret that never
 *   leaves the server and is restored when switching back; the parked token
 *   stays visible (and revocable) in the impersonator's session list;
 * - the impersonated user's session token is named "Impersonated by <uid>"
 *   so the impersonated user and admins can see and revoke it;
 * - app passwords minted for the impersonated user during the impersonation
 *   are revoked when the impersonation ends, a URL signing key created during
 *   it is removed (CredentialCleanup);
 * - the impersonator's stored password is re-checked periodically, so a
 *   password change of the impersonator ends the impersonation (sessions
 *   without a stored password, e.g. single sign-on, are bounded by the
 *   maximum duration only);
 * - every impersonation has a server side record (ActiveImpersonations), so
 *   one whose session just expires is still cleaned up and reported as ended;
 * - a failure while switching in either direction ends in a logged out
 *   session, never in a half switched one.
 */
class Util {
	public const SESSION_IMPERSONATOR = 'impersonator';
	public const SESSION_TARGET = 'impersonationTarget';
	public const SESSION_PARKED_TOKEN = 'impersonatorParkedToken';
	public const SESSION_IDENTITY_STASH = 'impersonatorIdentityStash';
	public const SESSION_START = 'impersonationStart';
	public const SESSION_TOKEN_WATERMARK = 'impersonationTokenWatermark';
	public const SESSION_ENCRYPTION_INITIALIZED = 'impersonatorEncryptionInitialized';
	public const SESSION_PRIVATE_KEY = 'impersonatorPrivateKey';
	public const SESSION_SIGNING_KEY_EXISTED = 'impersonationSigningKeyExisted';
	public const SESSION_RECORD = 'impersonationRecord';
	public const SESSION_TOKEN_ID = 'impersonationToken';
	private const SESSION_ROTATION_MARKER = 'impersonationRotation';

	public const REASON_RETURNED = 'the impersonator logged out and returned to the own session';
	public const REASON_LOGOUT = 'the session was logged out';
	public const REASON_SWITCH_BACK_FAILED = 'the session could not be switched back to the impersonator';
	public const REASON_ENDED_ELSEWHERE = 'the impersonation was ended by the background job or an administrator';
	public const REASON_OTHER_SESSION = 'the session is not bound to the session token of the impersonation anymore';

	/**
	 * Session keys that belong to the identity of the logged in user and must
	 * neither be used by the impersonated session nor leak back.
	 */
	public const IDENTITY_KEYS = [
		'loginname',
		'app_password',
		'last_check_timeout',
		// files_external "Log-in credentials, save in session" (contains the login password)
		'password::sessioncredentials/credentials',
		// \OCA\DAV\Connector\Sabre\Auth::DAV_AUTHENTICATED
		'AUTHENTICATED_TO_DAV_BACKEND',
	];

	/** session key of the encryption state => session key of the impersonator's copy */
	private const ENCRYPTION_KEYS = [
		'encryptionInitialized' => self::SESSION_ENCRYPTION_INITIALIZED,
		'privateKey' => self::SESSION_PRIVATE_KEY,
	];

	/** @var ISession */
	private $session;
	/** @var Session */
	private $userSession;
	/** @var DefaultTokenProvider */
	private $tokenProvider;
	/** @var IUserManager */
	private $userManager;
	/** @var ISecureRandom */
	private $secureRandom;
	/** @var CsrfTokenManager */
	private $csrfTokenManager;
	/** @var ILogger */
	private $logger;
	/** @var IConfig */
	private $config;
	/** @var ActiveImpersonations */
	private $registry;
	/** @var CredentialCleanup */
	private $cleanup;
	/** @var AuditTrail */
	private $auditTrail;
	/** @var Policy */
	private $policy;

	public function __construct(
		ISession $session,
		Session $userSession,
		DefaultTokenProvider $tokenProvider,
		IUserManager $userManager,
		ISecureRandom $secureRandom,
		CsrfTokenManager $csrfTokenManager,
		ILogger $logger,
		IConfig $config,
		ActiveImpersonations $registry,
		CredentialCleanup $cleanup,
		AuditTrail $auditTrail,
		Policy $policy
	) {
		$this->session = $session;
		$this->userSession = $userSession;
		$this->tokenProvider = $tokenProvider;
		$this->userManager = $userManager;
		$this->secureRandom = $secureRandom;
		$this->csrfTokenManager = $csrfTokenManager;
		$this->logger = $logger;
		$this->config = $config;
		$this->registry = $registry;
		$this->cleanup = $cleanup;
		$this->auditTrail = $auditTrail;
		$this->policy = $policy;
	}

	public function isImpersonating(): bool {
		return $this->session->get(self::SESSION_IMPERSONATOR) !== null;
	}

	/**
	 * @return string|null uid of the impersonator
	 */
	public function getImpersonatorUid(): ?string {
		$uid = $this->session->get(self::SESSION_IMPERSONATOR);
		return \is_string($uid) ? $uid : null;
	}

	/**
	 * @return string|null uid of the impersonated user as recorded when the
	 *                     impersonation started (null: none, or a session that
	 *                     was switched by a version that did not record it)
	 */
	public function getTargetUid(): ?string {
		$uid = $this->session->get(self::SESSION_TARGET);
		return \is_string($uid) && $uid !== '' ? $uid : null;
	}

	/**
	 * @return int|null unix time the impersonation started
	 */
	public function getStartTime(): ?int {
		$start = $this->session->get(self::SESSION_START);
		return \is_int($start) ? $start : null;
	}

	/**
	 * Has the impersonation of this session been ended outside of it (by the
	 * reconcile job, by an administrator, or because its session token was
	 * used elsewhere)? Then its record is gone or only waits for a cleanup.
	 * Sessions that were switched before records existed have none.
	 *
	 * @throws \Exception if the record can not be read
	 */
	public function hasEndedElsewhere(): bool {
		return $this->isClosedElsewhere($this->getRecordId());
	}

	/**
	 * Is the session still bound to the session token the impersonation was
	 * started with? An impersonated session whose id changed (and that got or
	 * lost a token on the way) is not the session that was authorized.
	 * Sessions that were switched before the token was recorded pass.
	 */
	public function isBoundToItsToken(): bool {
		$tokenId = $this->getTokenId();
		if ($tokenId === null) {
			return true;
		}
		$current = $this->findToken($this->currentSessionId());
		return $current !== null && (int)$current->getId() === $tokenId;
	}

	/**
	 * What this session could be presented with as a token: its id and the
	 * token a login with a token left in it.
	 *
	 * @return string[]
	 */
	public function getSessionSecrets(): array {
		$secrets = [];
		$sessionId = $this->currentSessionId();
		if ($sessionId !== null && $sessionId !== '') {
			$secrets[] = $sessionId;
		}
		$appPassword = $this->session->get('app_password');
		if (\is_string($appPassword) && $appPassword !== '') {
			$secrets[] = $appPassword;
		}
		return $secrets;
	}

	/**
	 * Replace the session of $impersonator by a session of $target.
	 *
	 * @throws RefusedException if the session is not one an impersonation may start
	 *                          from; nothing was changed
	 * @throws \Exception if the current session cannot be switched; the session is
	 *                    logged out if it was already partially switched
	 */
	public function startImpersonation(IUser $target, IUser $impersonator): void {
		if ($this->isImpersonating()) {
			throw new \LogicException('Nested impersonation is not supported');
		}
		// everything that can fail is done before the session or any token is changed
		$oldSessionId = $this->session->getId();
		[$loginName, $tokenName, $password] = $this->describeSession($oldSessionId, $impersonator);
		$hadSigningKey = $this->cleanup->hasSigningKey($target);
		$stash = [];
		foreach (self::IDENTITY_KEYS as $key) {
			$value = $this->session->get($key);
			if ($value !== null) {
				$stash[$key] = $value;
			}
		}
		$encodedStash = \json_encode($stash, JSON_THROW_ON_ERROR);
		$parkedSecret = $this->secureRandom->generate(
			64,
			ISecureRandom::CHAR_UPPER . ISecureRandom::CHAR_LOWER . ISecureRandom::CHAR_DIGITS
		);
		$start = \time();

		// park the impersonator's token under a secret that only lives in the (encrypted) session
		$this->tokenProvider->generateToken(
			$parkedSecret,
			$impersonator->getUID(),
			$loginName,
			$password,
			$tokenName,
			IToken::TEMPORARY_TOKEN
		);

		$recordId = null;
		$tokenId = null;
		try {
			$this->tokenProvider->invalidateToken($oldSessionId);

			// move identity bound session values out of the way
			foreach (self::IDENTITY_KEYS as $key) {
				$this->session->remove($key);
			}

			// Keep a copy of the impersonator's encryption keys to restore them later,
			// the "privateKey" var gets removed on logout. The keys stay active because
			// in master key mode every user needs them.
			foreach (self::ENCRYPTION_KEYS as $key => $copy) {
				$value = $this->session->get($key);
				if ($value !== null) {
					$this->session->set($copy, $value);
				}
			}

			// The impersonation is marked before the user of the session changes: a
			// request that dies in between leaves a session the guard ends, never a
			// session of the target that nothing knows to be an impersonation.
			$this->session->set(self::SESSION_IMPERSONATOR, $impersonator->getUID());
			$this->session->set(self::SESSION_TARGET, $target->getUID());
			$this->session->set(self::SESSION_PARKED_TOKEN, $parkedSecret);
			$this->session->set(self::SESSION_IDENTITY_STASH, $encodedStash);
			$this->session->set(self::SESSION_START, $start);
			$this->session->set(self::SESSION_SIGNING_KEY_EXISTED, $hadSigningKey);

			$this->rotateSessionId();
			$sessionToken = $this->tokenProvider->generateToken(
				$this->session->getId(),
				$target->getUID(),
				$target->getUID(),
				null,
				self::impersonationTokenName($impersonator->getUID()),
				IToken::TEMPORARY_TOKEN
			);
			// Tokens are numbered in the order they are created: every token the target
			// gets from now on has a higher id than this one.
			$tokenId = (int)$sessionToken->getId();
			$this->session->set(self::SESSION_TOKEN_ID, $tokenId);
			$this->session->set(self::SESSION_TOKEN_WATERMARK, $tokenId);
			$recordId = $this->registry->open([
				'impersonator' => $impersonator->getUID(),
				'target' => $target->getUID(),
				'token' => $tokenId,
				'signingKey' => $hadSigningKey,
				'start' => $start,
				// how long an id of this session is: lets the guard recognize it in a request
				'sid' => \strlen((string)$this->session->getId()),
			]);
			$this->session->set(self::SESSION_RECORD, $recordId);

			$this->userSession->setUser($target);
			$this->userSession->setLoginName($target->getUID());
			$this->csrfTokenManager->refreshToken();
		} catch (\Throwable $e) {
			// fail closed: a partially switched session must not survive
			$this->logger->logException($e, ['app' => 'impersonate']);
			try {
				$this->tokenProvider->invalidateToken($parkedSecret);
			} catch (\Throwable $ignored) {
			}
			// whatever happens to the logout: the session has no valid token anymore
			$revoked = $this->invalidateCurrentSessionToken();
			if ($tokenId !== null) {
				$revoked = $this->cleanup->revokeSessionToken($target, $tokenId) && $revoked;
			}
			try {
				if ($revoked) {
					if ($recordId !== null) {
						$this->registry->close($recordId);
					}
				} elseif ($tokenId !== null) {
					// The token of the half switched session may still be valid: a record
					// keeps it known (ImpersonationGuard) until the reconcile job revoked it.
					$record = [
						'impersonator' => $impersonator->getUID(),
						'target' => $target->getUID(),
						'token' => $tokenId,
						'signingKey' => $hadSigningKey,
						'start' => $start,
						'sid' => \strlen((string)$this->currentSessionId()),
					];
					$recordId = $recordId ?? $this->registry->open($record);
					$this->registry->markPending($recordId, $record, \time());
				}
			} catch (\Throwable $ignored) {
			}
			$this->clearImpersonationState();
			foreach (self::ENCRYPTION_KEYS as $copy) {
				$this->session->remove($copy);
			}
			try {
				$this->userSession->logout();
			} catch (\Throwable $ignored) {
			}
			throw new \RuntimeException('Switching the session failed, the session was logged out', 0, $e);
		}
	}

	/**
	 * Switch the session back to the impersonator.
	 *
	 * @return bool true if the session now belongs to the impersonator again;
	 *              false if that was not possible, in which case the impersonation
	 *              has been ended and cleaned up and the caller must log the
	 *              session out
	 */
	public function stopImpersonation(): bool {
		$impersonatorUid = $this->getImpersonatorUid();
		if ($impersonatorUid === null) {
			return false;
		}
		$targetUid = $this->getTargetUid();
		$recordId = $this->getRecordId();
		$tokenId = $this->getTokenId();
		$result = ['tokens' => true, 'signingKey' => true, 'ceiling' => null];
		try {
			$impersonator = $this->userManager->get($impersonatorUid);
			$target = $this->userSession->getUser();
			$parkedSecret = $this->session->get(self::SESSION_PARKED_TOKEN);
			$parkedToken = \is_string($parkedSecret) && $parkedSecret !== '' ? $this->findToken($parkedSecret) : null;
			$currentToken = $this->findToken($this->currentSessionId());
			if ($impersonator === null || !$impersonator->isEnabled()
				|| $parkedToken === null || $parkedToken->getUID() !== $impersonator->getUID()
				// the impersonated session itself must still be valid (not revoked) ...
				|| $target === null || $currentToken === null || $currentToken->getUID() !== $target->getUID()
				|| ($targetUid !== null && $target->getUID() !== $targetUid)
				// ... and the one the impersonation was started in
				|| ($tokenId !== null && (int)$currentToken->getId() !== $tokenId)
				// the reconcile job or an administrator has already ended this impersonation
				|| $this->isClosedElsewhere($recordId)
			) {
				$this->endImpersonation(self::REASON_SWITCH_BACK_FAILED);
				return false;
			}
			$targetUid = $target->getUID();
			try {
				$password = $this->tokenProvider->getPassword($parkedToken, (string)$parkedSecret);
			} catch (PasswordlessTokenException $e) {
				$password = null;
			} catch (InvalidTokenException $e) {
				$this->endImpersonation(self::REASON_SWITCH_BACK_FAILED);
				return false;
			}

			// The session of the impersonated user ends here. If its token can not be
			// revoked, nothing is switched: the impersonation is ended instead (below).
			$this->tokenProvider->invalidateToken($this->session->getId());
			$result = $this->cleanUpCredentials($target);

			// drop whatever the impersonated session stored, restore the impersonator's values
			foreach (self::IDENTITY_KEYS as $key) {
				$this->session->remove($key);
			}
			foreach ($this->getStash() as $key => $value) {
				if (\in_array($key, self::IDENTITY_KEYS, true)) {
					$this->session->set($key, $value);
				}
			}
			$this->restoreEncryptionKeys();

			$this->rotateSessionId();
			$this->tokenProvider->generateToken(
				$this->session->getId(),
				$impersonator->getUID(),
				$parkedToken->getLoginName(),
				$password,
				self::tokenName($parkedToken),
				IToken::TEMPORARY_TOKEN
			);
			$this->tokenProvider->invalidateToken((string)$parkedSecret);
			$this->userSession->setUser($impersonator);
			$this->userSession->setLoginName($parkedToken->getLoginName());
			$this->csrfTokenManager->refreshToken();
			$this->clearImpersonationState();
		} catch (\Throwable $e) {
			// fail closed like the start: no half restored session, the caller logs out
			$this->logger->logException($e, ['app' => 'impersonate']);
			$this->endImpersonation(self::REASON_SWITCH_BACK_FAILED);
			return false;
		}
		$this->settleRecord($recordId, true, $result);
		$this->auditTrail->ended($impersonatorUid, $targetUid, self::REASON_RETURNED);
		return true;
	}

	/**
	 * End the impersonation without switching back: revoke everything that was
	 * created for it (its session token by the recorded id, and the token of
	 * the current session) and remove the impersonation state from the session.
	 * What could not be revoked is left to the reconcile job; the record of the
	 * impersonation keeps its token known until then. Never throws. The caller
	 * is expected to log the session out afterwards.
	 *
	 * @param string $reason why it ends, for the audit event
	 */
	public function endImpersonation(string $reason): void {
		$impersonatorUid = $this->getImpersonatorUid();
		if ($impersonatorUid === null) {
			return;
		}
		$recordId = $this->getRecordId();
		$targetUid = $this->getTargetUid();
		$tokenId = $this->getTokenId();
		// what the cleanup achieved; "not done" until it ran
		$result = ['tokens' => false, 'signingKey' => false, 'ceiling' => null];
		$revoked = false;
		$closedElsewhere = false;
		try {
			$closedElsewhere = $this->isClosedElsewhere($recordId);
		} catch (\Throwable $e) {
			$this->logger->logException($e, ['app' => 'impersonate']);
		}
		$cleaned = false;
		try {
			$target = $targetUid !== null ? $this->userManager->get($targetUid) : $this->userSession->getUser();
			if ($target !== null) {
				$targetUid = $targetUid ?? $target->getUID();
				// Was the session token of the impersonation still valid? If the impersonation
				// was ended elsewhere and its token revoked there, this session could not act
				// since: whatever appeared for the user after that is none of its doing, and a
				// second cleanup would only hit credentials of the account owner.
				$sessionWasAlive = true;
				if ($closedElsewhere && $tokenId !== null) {
					try {
						$sessionWasAlive = $this->cleanup->hasSessionToken($target, $tokenId);
					} catch (\Throwable $e) {
						// not known: as if it was
						$this->logger->logException($e, ['app' => 'impersonate']);
					}
				}
				// wherever the session is now: the token it was started with
				$revoked = $tokenId === null || $this->cleanup->revokeSessionToken($target, $tokenId);
				if ($sessionWasAlive) {
					$result = $this->cleanUpCredentials($target);
					$cleaned = true;
				} else {
					$result = ['tokens' => true, 'signingKey' => true, 'ceiling' => null];
				}
			} elseif ($targetUid === null) {
				// a session without a user and without a recorded target: nothing is known to clean
				$revoked = true;
				$result = ['tokens' => true, 'signingKey' => true, 'ceiling' => null];
			}
			// else: the user was deleted (nothing is left to revoke) or can not be loaded right
			// now (nothing can be revoked): the reconcile job finds out which
		} catch (\Throwable $e) {
			$this->logger->logException($e, ['app' => 'impersonate']);
		}
		try {
			$parkedSecret = $this->session->get(self::SESSION_PARKED_TOKEN);
			if (\is_string($parkedSecret) && $parkedSecret !== '') {
				$this->tokenProvider->invalidateToken($parkedSecret);
			}
		} catch (\Throwable $e) {
			// it can not be used without its secret, which only this session had
			$this->logger->logException($e, ['app' => 'impersonate']);
		}
		// the session must not go on as the impersonated user, whatever happens to the logout that follows
		$revoked = $this->invalidateCurrentSessionToken() && $revoked;
		try {
			foreach (self::IDENTITY_KEYS as $key) {
				$this->session->remove($key);
			}
			foreach (self::ENCRYPTION_KEYS as $copy) {
				$this->session->remove($copy);
			}
			$this->clearImpersonationState();
		} catch (\Throwable $e) {
			$this->logger->logException($e, ['app' => 'impersonate']);
		}
		if ($closedElsewhere) {
			// Reported where it was ended. A record that waits for its cleanup learns what this
			// session achieved (it was still alive, so the earlier attempt could not be the last).
			if ($cleaned) {
				$this->settleRecord($recordId, $revoked, $result);
			}
			return;
		}
		$this->settleRecord($recordId, $revoked, $result);
		$this->auditTrail->ended($impersonatorUid, $targetUid ?? '', $reason);
	}

	/**
	 * Is the impersonator's parked session still valid? Like core does for normal
	 * sessions, the stored login password is re-checked every "last_check_timeout"
	 * minutes, so changing the impersonator's password ends the impersonation.
	 * A parked token without a stored password (the impersonator logged in without
	 * one, e.g. by single sign-on) has nothing to re-check; such an impersonation is
	 * bounded by the maximum duration (Policy::getMaxDuration()).
	 * Refreshes the token activity so that the token cleanup job keeps it.
	 */
	public function touchParkedToken(): bool {
		$parkedSecret = $this->session->get(self::SESSION_PARKED_TOKEN);
		if (!\is_string($parkedSecret) || $parkedSecret === '') {
			return false;
		}
		$token = $this->findToken($parkedSecret);
		if ($token === null || $token->getUID() !== $this->getImpersonatorUid()) {
			return false;
		}
		$now = \time();
		$timeout = 60 * (int)$this->config->getAppValue('core', 'last_check_timeout', 5);
		if ((int)$token->getLastCheck() <= $now - $timeout) {
			try {
				$password = $this->tokenProvider->getPassword($token, $parkedSecret);
			} catch (PasswordlessTokenException $e) {
				$password = null;
			} catch (InvalidTokenException $e) {
				return false;
			}
			if ($password !== null && $this->userManager->checkPassword($token->getLoginName(), $password) === false) {
				$this->logger->warning(
					'The password of impersonator "{impersonator}" has changed',
					['app' => 'impersonate', 'impersonator' => $token->getUID()]
				);
				$this->tokenProvider->invalidateToken($parkedSecret);
				return false;
			}
			$token->setLastCheck($now);
			$this->tokenProvider->updateToken($token);
		}
		$this->tokenProvider->updateTokenActivity($token);
		return true;
	}

	public static function impersonationTokenName(string $impersonatorUid): string {
		return \mb_substr('Impersonated by ' . $impersonatorUid, 0, 120);
	}

	private static function tokenName(IToken $token): string {
		if ($token instanceof DefaultToken && \is_string($token->getName())) {
			return $token->getName();
		}
		return 'unknown browser';
	}

	/**
	 * Login name, token name and stored password of the session that is about to be parked.
	 * Runs before anything is changed.
	 *
	 * @return array{0: string, 1: string, 2: string|null}
	 * @throws RefusedException if the request has no session token of its own (it is
	 *                          authenticated by HTTP Basic credentials, an app password, ...):
	 *                          there is no interactive session to park and to return to
	 */
	private function describeSession(string $sessionId, IUser $user): array {
		try {
			$token = $this->tokenProvider->getToken($sessionId);
		} catch (InvalidTokenException $e) {
			throw new RefusedException('an impersonation must be started from an interactive session', 0, $e);
		}
		if ($token->getUID() !== $user->getUID()) {
			throw new RefusedException('the session token does not belong to the current user');
		}
		// The platform also gives a request that authenticates itself (HTTP Basic, a token)
		// a session with a session token once it carries a cookie. Such a session is marked:
		// it holds the token it was logged in with, or the DAV marker of HTTP Basic.
		if (!$this->policy->allowsStartWithCredentials()) {
			foreach (['app_password', 'AUTHENTICATED_TO_DAV_BACKEND'] as $marker) {
				if ($this->session->get($marker) !== null) {
					throw new RefusedException(
						'an impersonation must be started from an interactive session (the session was authenticated by a request with credentials)'
					);
				}
			}
		}
		try {
			$password = $this->tokenProvider->getPassword($token, $sessionId);
		} catch (PasswordlessTokenException $e) {
			// e.g. single sign-on: no password to re-check, bounded by the maximum duration
			$password = null;
		}
		return [$token->getLoginName(), self::tokenName($token), $password];
	}

	private function findToken(?string $tokenId): ?IToken {
		if ($tokenId === null || $tokenId === '') {
			return null;
		}
		try {
			return $this->tokenProvider->getToken($tokenId);
		} catch (InvalidTokenException $e) {
			return null;
		}
	}

	private function currentSessionId(): ?string {
		try {
			return $this->session->getId();
		} catch (\Exception $e) {
			return null;
		}
	}

	/**
	 * Give the session a new id. The old session file does not keep any
	 * authenticated state: CryptoSessionData::remove() drops the encrypted data
	 * from the PHP session, so requests that still carry the old id (e.g. queued
	 * on the session lock) see an anonymous session instead of a session whose
	 * token is gone (which would make core log the whole browser out).
	 */
	private function rotateSessionId(): void {
		$this->session->remove(self::SESSION_ROTATION_MARKER);
		$this->session->regenerateId(false);
	}

	private function getRecordId(): ?string {
		$id = $this->session->get(self::SESSION_RECORD);
		return \is_string($id) && $id !== '' ? $id : null;
	}

	/**
	 * @return int|null id of the session token the impersonation was started with
	 */
	private function getTokenId(): ?int {
		$id = $this->session->get(self::SESSION_TOKEN_ID);
		return \is_int($id) ? $id : null;
	}

	/**
	 * Has the reconcile job (or an administrator) already ended the impersonation
	 * this session belongs to? Then it was reported there.
	 */
	private function isClosedElsewhere(?string $recordId): bool {
		if ($recordId === null) {
			// a session that was switched before records existed
			return false;
		}
		$record = $this->registry->get($recordId);
		return $record === null || isset($record['pending']);
	}

	/**
	 * Close the record of the impersonation, or keep it for the reconcile job if
	 * something has to be retried. Never throws.
	 *
	 * @param bool $revoked the session token of the impersonation is revoked
	 * @param array{tokens: bool, signingKey: bool, ceiling: int|null} $cleanup what the cleanup achieved
	 */
	private function settleRecord(?string $recordId, bool $revoked, array $cleanup): void {
		if ($recordId === null) {
			return;
		}
		try {
			if ($revoked && $cleanup['tokens'] && $cleanup['signingKey']) {
				$this->registry->close($recordId);
				return;
			}
			$record = $this->registry->get($recordId);
			if ($record !== null) {
				$this->registry->markPending(
					$recordId,
					$record,
					\time(),
					// only once the session is known to be over is what appears later none of its doing
					$revoked ? $cleanup['ceiling'] : null,
					$cleanup['signingKey']
				);
			}
		} catch (\Throwable $e) {
			$this->logger->logException($e, ['app' => 'impersonate']);
		}
	}

	/**
	 * Remove the credentials of the impersonated user that appeared during the
	 * impersonation (see CredentialCleanup). Never throws.
	 *
	 * @return array{tokens: bool, signingKey: bool, ceiling: int|null} see CredentialCleanup::run()
	 */
	private function cleanUpCredentials(IUser $target): array {
		$watermark = $this->session->get(self::SESSION_TOKEN_WATERMARK);
		if (!\is_int($watermark)) {
			// the switch never got as far as a session of the target
			return ['tokens' => true, 'signingKey' => true, 'ceiling' => null];
		}
		// Left alone whatever they look like: the session tokens of other impersonations of
		// the same user, and the token of this session (it is revoked by its own means; a
		// session that was switched by an older version has a mark below its own token).
		$keep = [];
		try {
			$keep = ActiveImpersonations::tokenIds($this->registry->all());
			$current = $this->findToken($this->currentSessionId());
			if ($current !== null) {
				$keep[] = (int)$current->getId();
			}
		} catch (\Throwable $e) {
			$this->logger->logException($e, ['app' => 'impersonate']);
		}
		return $this->cleanup->run(
			$target,
			$watermark,
			// only a recorded "there was none" allows the removal
			$this->session->get(self::SESSION_SIGNING_KEY_EXISTED) !== false,
			$this->getImpersonatorUid(),
			null,
			$keep
		);
	}

	private function clearImpersonationState(): void {
		foreach ([
			self::SESSION_IMPERSONATOR,
			self::SESSION_TARGET,
			self::SESSION_PARKED_TOKEN,
			self::SESSION_IDENTITY_STASH,
			self::SESSION_START,
			self::SESSION_TOKEN_WATERMARK,
			self::SESSION_TOKEN_ID,
			self::SESSION_SIGNING_KEY_EXISTED,
			self::SESSION_RECORD,
		] as $key) {
			$this->session->remove($key);
		}
	}

	/**
	 * Return to exactly the encryption state the impersonator's session had before
	 * the impersonation: a value the session got while impersonating does not stay.
	 */
	private function restoreEncryptionKeys(): void {
		foreach (self::ENCRYPTION_KEYS as $key => $copy) {
			$saved = $this->session->get($copy);
			if ($saved !== null) {
				$this->session->set($key, $saved);
			} else {
				$this->session->remove($key);
			}
			$this->session->remove($copy);
		}
	}

	/**
	 * @return array<string, mixed>
	 */
	private function getStash(): array {
		$raw = $this->session->get(self::SESSION_IDENTITY_STASH);
		if (!\is_string($raw)) {
			return [];
		}
		$stash = \json_decode($raw, true);
		return \is_array($stash) ? $stash : [];
	}

	/**
	 * @return bool false if the token of the current session could not be invalidated
	 */
	private function invalidateCurrentSessionToken(): bool {
		try {
			$this->tokenProvider->invalidateToken($this->session->getId());
			return true;
		} catch (\Throwable $e) {
			$this->logger->logException($e, ['app' => 'impersonate']);
			return false;
		}
	}
}
