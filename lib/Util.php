<?php
/**
 * Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
 * Maintained by Marek Królikowski (TaKeN): https://github.com/takenek/impersonate
 * Modified on 2026-11-26 by Marek Królikowski (TaKeN): ownCloud 11.1 support and security
 * hardening, see CHANGELOG.md. SPDX-License-Identifier: AGPL-3.0-only
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
use OCP\IRequest;
use OCP\ISession;
use OCP\IUser;
use OCP\IUserManager;
use OCP\Security\ISecureRandom;

/**
 * Switches the logged in user of the current session between the
 * impersonator and the impersonated user.
 *
 * Security properties:
 * - session values bound to the impersonator's identity (login name, the
 *   password kept for "log-in credentials, save in session" external
 *   storages, app password and DAV markers) are removed from the session
 *   while impersonating and restored afterwards;
 * - the session id and the CSRF token are rotated on every switch;
 * - the impersonator's own session token (including the stored login
 *   password) is parked under a random secret that never leaves the server
 *   and is restored when switching back, so the impersonator keeps a
 *   password-bound session; the parked token stays visible (and revocable)
 *   in the impersonator's session list;
 * - the impersonated user's session token is named "Impersonated by <uid>"
 *   so the impersonated user and admins can see and revoke it;
 * - app passwords minted for the impersonated user during the impersonation
 *   are revoked when the impersonation ends, a URL signing key created during
 *   it is removed;
 * - the impersonator's stored password is re-checked periodically, so a
 *   password change of the impersonator ends the impersonation.
 */
class Util {
	public const SESSION_IMPERSONATOR = 'impersonator';
	public const SESSION_PARKED_TOKEN = 'impersonatorParkedToken';
	public const SESSION_IDENTITY_STASH = 'impersonatorIdentityStash';
	public const SESSION_START = 'impersonationStart';
	public const SESSION_TOKEN_WATERMARK = 'impersonationTokenWatermark';
	public const SESSION_ENCRYPTION_INITIALIZED = 'impersonatorEncryptionInitialized';
	public const SESSION_PRIVATE_KEY = 'impersonatorPrivateKey';
	public const SESSION_SIGNING_KEY_EXISTED = 'impersonationSigningKeyExisted';
	private const SESSION_ROTATION_MARKER = 'impersonationRotation';

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

	/** @var ISession */
	private $session;
	/** @var Session */
	private $userSession;
	/** @var IRequest */
	private $request;
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

	public function __construct(
		ISession $session,
		Session $userSession,
		IRequest $request,
		DefaultTokenProvider $tokenProvider,
		IUserManager $userManager,
		ISecureRandom $secureRandom,
		CsrfTokenManager $csrfTokenManager,
		ILogger $logger,
		IConfig $config
	) {
		$this->session = $session;
		$this->userSession = $userSession;
		$this->request = $request;
		$this->tokenProvider = $tokenProvider;
		$this->userManager = $userManager;
		$this->secureRandom = $secureRandom;
		$this->csrfTokenManager = $csrfTokenManager;
		$this->logger = $logger;
		$this->config = $config;
	}

	public static function fromServer(): self {
		$server = \OC::$server;
		/** @var Session $userSession */
		$userSession = $server->getUserSession();
		/** @var DefaultTokenProvider $tokenProvider */
		$tokenProvider = $server->query(DefaultTokenProvider::class);
		/** @var CsrfTokenManager $csrfTokenManager */
		$csrfTokenManager = $server->getCsrfTokenManager();
		return new self(
			$server->getSession(),
			$userSession,
			$server->getRequest(),
			$tokenProvider,
			$server->getUserManager(),
			$server->getSecureRandom(),
			$csrfTokenManager,
			$server->getLogger(),
			$server->getConfig()
		);
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
	 * Replace the session of $impersonator by a session of $target.
	 *
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
		$watermark = $this->getHighestTokenId($target);
		$hadSigningKey = $this->hasSigningKey($target);
		$parkedSecret = $this->secureRandom->generate(
			64,
			ISecureRandom::CHAR_UPPER . ISecureRandom::CHAR_LOWER . ISecureRandom::CHAR_DIGITS
		);

		// park the impersonator's token under a secret that only lives in the (encrypted) session
		$this->tokenProvider->generateToken(
			$parkedSecret,
			$impersonator->getUID(),
			$loginName,
			$password,
			$tokenName,
			IToken::TEMPORARY_TOKEN
		);

		try {
			$this->tokenProvider->invalidateToken($oldSessionId);

			// move identity bound session values out of the way
			$stash = [];
			foreach (self::IDENTITY_KEYS as $key) {
				$value = $this->session->get($key);
				if ($value !== null) {
					$stash[$key] = $value;
				}
				$this->session->remove($key);
			}

			// Keep a copy of the impersonator's encryption keys to restore them later,
			// the "privateKey" var gets removed on logout. The keys stay active because
			// in master key mode every user needs them.
			$encryptionInitialized = $this->session->get('encryptionInitialized');
			if ($encryptionInitialized !== null) {
				$this->session->set(self::SESSION_ENCRYPTION_INITIALIZED, $encryptionInitialized);
			}
			$privateKey = $this->session->get('privateKey');
			if ($privateKey !== null) {
				$this->session->set(self::SESSION_PRIVATE_KEY, $privateKey);
			}

			$this->rotateSessionId();
			$this->tokenProvider->generateToken(
				$this->session->getId(),
				$target->getUID(),
				$target->getUID(),
				null,
				self::impersonationTokenName($impersonator->getUID()),
				IToken::TEMPORARY_TOKEN
			);
			$this->userSession->setUser($target);
			$this->userSession->setLoginName($target->getUID());

			$this->session->set(self::SESSION_IMPERSONATOR, $impersonator->getUID());
			$this->session->set(self::SESSION_PARKED_TOKEN, $parkedSecret);
			$this->session->set(self::SESSION_IDENTITY_STASH, \json_encode($stash));
			$this->session->set(self::SESSION_START, \time());
			$this->session->set(self::SESSION_TOKEN_WATERMARK, $watermark);
			$this->session->set(self::SESSION_SIGNING_KEY_EXISTED, $hadSigningKey);
			$this->csrfTokenManager->refreshToken();
		} catch (\Throwable $e) {
			// fail closed: a partially switched session must not survive
			$this->logger->logException($e, ['app' => 'impersonate']);
			try {
				$this->tokenProvider->invalidateToken($parkedSecret);
			} catch (\Throwable $ignored) {
			}
			$this->clearImpersonationState();
			$this->session->remove(self::SESSION_ENCRYPTION_INITIALIZED);
			$this->session->remove(self::SESSION_PRIVATE_KEY);
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
	 *              has been cleaned up and the caller must log the session out
	 */
	public function stopImpersonation(): bool {
		$impersonatorUid = $this->getImpersonatorUid();
		if ($impersonatorUid === null) {
			return false;
		}
		$impersonator = $this->userManager->get($impersonatorUid);
		$target = $this->userSession->getUser();
		$parkedSecret = $this->session->get(self::SESSION_PARKED_TOKEN);
		$parkedToken = \is_string($parkedSecret) && $parkedSecret !== '' ? $this->findToken($parkedSecret) : null;
		$currentToken = $this->findToken($this->currentSessionId());
		if ($impersonator === null || !$impersonator->isEnabled()
			|| $parkedToken === null || $parkedToken->getUID() !== $impersonator->getUID()
			// the impersonated session itself must still be valid (not revoked)
			|| $target === null || $currentToken === null || $currentToken->getUID() !== $target->getUID()
		) {
			$this->endImpersonation();
			return false;
		}
		try {
			$password = $this->tokenProvider->getPassword($parkedToken, (string)$parkedSecret);
		} catch (PasswordlessTokenException $e) {
			$password = null;
		} catch (InvalidTokenException $e) {
			$this->endImpersonation();
			return false;
		}

		$this->revokeTokensMintedDuringImpersonation();
		$this->removeSigningKeyCreatedDuringImpersonation();
		$this->invalidateCurrentSessionToken();

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
		$this->clearImpersonationState();
		$this->csrfTokenManager->refreshToken();
		return true;
	}

	/**
	 * End the impersonation without switching back: revoke everything that was
	 * created for it and remove the impersonation state from the session.
	 * The caller is expected to log the session out afterwards.
	 */
	public function endImpersonation(): void {
		if (!$this->isImpersonating()) {
			return;
		}
		$this->revokeTokensMintedDuringImpersonation();
		$this->removeSigningKeyCreatedDuringImpersonation();
		$parkedSecret = $this->session->get(self::SESSION_PARKED_TOKEN);
		if (\is_string($parkedSecret) && $parkedSecret !== '') {
			$this->tokenProvider->invalidateToken($parkedSecret);
		}
		foreach (self::IDENTITY_KEYS as $key) {
			$this->session->remove($key);
		}
		$this->session->remove(self::SESSION_ENCRYPTION_INITIALIZED);
		$this->session->remove(self::SESSION_PRIVATE_KEY);
		$this->clearImpersonationState();
	}

	/**
	 * Is the impersonator's parked session still valid? Like core does for normal
	 * sessions, the stored login password is re-checked every "last_check_timeout"
	 * minutes, so changing the impersonator's password ends the impersonation.
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
	 *
	 * @return array{0: string, 1: string, 2: string|null}
	 */
	private function describeSession(string $sessionId, IUser $user): array {
		try {
			$token = $this->tokenProvider->getToken($sessionId);
			try {
				$password = $this->tokenProvider->getPassword($token, $sessionId);
			} catch (PasswordlessTokenException $e) {
				$password = null;
			}
			return [$token->getLoginName(), self::tokenName($token), $password];
		} catch (InvalidTokenException $e) {
			// e.g. a request authenticated with basic auth: there is no session token yet
			$loginName = (string)$this->userSession->getLoginName();
			return [
				$loginName !== '' ? $loginName : $user->getUID(),
				$this->request->getHeader('User-Agent') ?: 'unknown browser',
				null,
			];
		}
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

	private function hasSigningKey(IUser $user): bool {
		return (string)$this->config->getUserValue($user->getUID(), 'core', 'signing-key', '') !== '';
	}

	/**
	 * The signing key allows pre-signed WebDAV URLs without a session. Reading it
	 * is refused while impersonating (ImpersonationGuard); as a backstop a key
	 * that was created during the impersonation is removed again.
	 */
	private function removeSigningKeyCreatedDuringImpersonation(): void {
		$target = $this->userSession->getUser();
		if ($target === null || $this->session->get(self::SESSION_SIGNING_KEY_EXISTED) !== false) {
			return;
		}
		try {
			if ($this->hasSigningKey($target)) {
				$this->config->deleteUserValue($target->getUID(), 'core', 'signing-key');
				$this->logger->warning(
					'Removed the URL signing key of user "{target}" created while "{impersonator}" impersonated them',
					['app' => 'impersonate', 'target' => $target->getUID(), 'impersonator' => $this->getImpersonatorUid()]
				);
			}
		} catch (\Exception $e) {
			$this->logger->logException($e, ['app' => 'impersonate']);
		}
	}

	private function clearImpersonationState(): void {
		foreach ([
			self::SESSION_IMPERSONATOR,
			self::SESSION_PARKED_TOKEN,
			self::SESSION_IDENTITY_STASH,
			self::SESSION_START,
			self::SESSION_TOKEN_WATERMARK,
			self::SESSION_SIGNING_KEY_EXISTED,
		] as $key) {
			$this->session->remove($key);
		}
	}

	private function restoreEncryptionKeys(): void {
		$encryptionInitialized = $this->session->get(self::SESSION_ENCRYPTION_INITIALIZED);
		if ($encryptionInitialized !== null) {
			$this->session->set('encryptionInitialized', $encryptionInitialized);
			$this->session->remove(self::SESSION_ENCRYPTION_INITIALIZED);
		}
		$privateKey = $this->session->get(self::SESSION_PRIVATE_KEY);
		if ($privateKey !== null) {
			$this->session->set('privateKey', $privateKey);
			$this->session->remove(self::SESSION_PRIVATE_KEY);
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

	private function invalidateCurrentSessionToken(): void {
		try {
			$this->tokenProvider->invalidateToken($this->session->getId());
		} catch (\Exception $e) {
			$this->logger->logException($e, ['app' => 'impersonate']);
		}
	}

	private function getHighestTokenId(IUser $user): int {
		$max = 0;
		foreach ($this->tokenProvider->getTokenByUser($user) as $token) {
			$max = \max($max, (int)$token->getId());
		}
		return $max;
	}

	/**
	 * Backstop for the app password block of ImpersonationGuard: app passwords
	 * created from the impersonated session are permanent and have no stored
	 * password. Such tokens created after the impersonation started are revoked.
	 * (The impersonated user's own passwordless app passwords created in the same
	 * time window, e.g. from an SSO session, are revoked as well.)
	 */
	private function revokeTokensMintedDuringImpersonation(): void {
		$watermark = $this->session->get(self::SESSION_TOKEN_WATERMARK);
		$impersonatorUid = $this->getImpersonatorUid();
		$target = $this->userSession->getUser();
		if (!\is_int($watermark) || $target === null) {
			return;
		}
		try {
			foreach ($this->tokenProvider->getTokenByUser($target) as $token) {
				if ($token instanceof DefaultToken
					&& (int)$token->getId() > $watermark
					&& (int)$token->getType() === IToken::PERMANENT_TOKEN
					// tokens minted from the impersonated session have no stored password
					&& (string)$token->getPassword() === ''
				) {
					$this->tokenProvider->invalidateTokenById($target, $token->getId());
					$this->logger->warning(
						'Revoked passwordless app password "{name}" of user "{target}" created during the impersonation by "{impersonator}"',
						[
							'app' => 'impersonate',
							'name' => $token->getName(),
							'target' => $target->getUID(),
							'impersonator' => $impersonatorUid,
						]
					);
				}
			}
		} catch (\Exception $e) {
			$this->logger->logException($e, ['app' => 'impersonate']);
		}
	}
}
