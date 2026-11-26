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
use OCP\IRequest;
use OCP\IUserManager;
use OCP\IUserSession;

/**
 * Request level checks while a session is impersonating somebody.
 * Runs (from appinfo/app.php) once all authentication apps are loaded and the
 * session was validated by core, before the request is routed.
 */
class ImpersonationGuard {
	/**
	 * Requests that would give the impersonator credentials that outlive the
	 * impersonation: [method or '*', path] (path as matched by the router)
	 */
	private const FORBIDDEN = [
		// core route settings.AuthSettings.create: app passwords
		['POST', '/settings/personal/authtokens'],
		// core route ocs.cloud.getSigningKey: key for pre-signed WebDAV URLs
		['*', '/cloud/user/signing-key'],
	];
	/** path prefixes forbidden for every method: OAuth2 authorization (refresh tokens) */
	private const FORBIDDEN_PREFIXES = [
		'/apps/oauth2/',
	];

	/** @var Util */
	private $util;
	/** @var Policy */
	private $policy;
	/** @var IUserSession */
	private $userSession;
	/** @var IUserManager */
	private $userManager;
	/** @var IRequest */
	private $request;
	/** @var ILogger */
	private $logger;

	public function __construct(
		Util $util,
		Policy $policy,
		IUserSession $userSession,
		IUserManager $userManager,
		IRequest $request,
		ILogger $logger
	) {
		$this->util = $util;
		$this->policy = $policy;
		$this->userSession = $userSession;
		$this->userManager = $userManager;
		$this->request = $request;
		$this->logger = $logger;
	}

	/** @var bool */
	private static $checked = false;

	/**
	 * Slot of the 'OC_App::loadedApps' hook (registered in appinfo/app.php): runs
	 * once per request, after all authentication apps (e.g. LDAP group backends)
	 * are loaded and core validated the session, before the request is routed.
	 *
	 * @codeCoverageIgnore
	 */
	public static function onLoadedApps(): void {
		if (self::$checked) {
			return;
		}
		self::$checked = true;
		try {
			$application = new AppInfo\Application();
			/** @var ImpersonationGuard $guard */
			$guard = $application->getContainer()->query(self::class);
			if ($guard->validate() && $guard->isForbiddenRequest()) {
				$guard->denyRequest();
			}
		} catch (\Throwable $e) {
			\OC::$server->getLogger()->logException($e, ['app' => 'impersonate']);
		}
	}

	/**
	 * End the impersonation (and log the session out) when the impersonator
	 * no longer exists, was disabled, lost the permission to impersonate the
	 * current user or when the impersonator's parked session was revoked.
	 *
	 * @return bool true if the impersonation is (still) valid or there is none
	 */
	public function validate(): bool {
		$impersonatorUid = $this->util->getImpersonatorUid();
		if ($impersonatorUid === null) {
			return true;
		}
		if (\OC_User::isIncognitoMode()) {
			// e.g. an update is pending: core hides the session user, nothing to decide now
			return true;
		}
		$target = $this->userSession->getUser();
		if ($target === null) {
			// the impersonated user is gone: end the impersonation for good
			$this->logger->warning(
				'Ending impersonation by "{impersonator}": the impersonated user does not exist anymore',
				['app' => 'impersonate', 'impersonator' => $impersonatorUid]
			);
			$this->util->endImpersonation();
			$this->userSession->logout();
			return false;
		}
		$impersonator = $this->userManager->get($impersonatorUid);
		$reason = null;
		if ($impersonator === null) {
			$reason = 'the impersonator does not exist anymore';
		} elseif (!$impersonator->isEnabled()) {
			$reason = 'the impersonator has been disabled';
		} elseif ($this->policy->check($impersonator, $target) !== null) {
			$reason = 'the impersonator is not allowed to impersonate this user anymore';
		} elseif (!$this->util->touchParkedToken()) {
			$reason = "the impersonator's own session was revoked or has expired";
		}
		if ($reason === null) {
			return true;
		}

		$this->logger->warning(
			'Ending impersonation of user "{target}" by "{impersonator}": {reason}',
			['app' => 'impersonate', 'target' => $target->getUID(), 'impersonator' => $impersonatorUid, 'reason' => $reason]
		);
		$this->util->endImpersonation();
		$this->userSession->logout();
		return false;
	}

	/**
	 * Requests that would give the impersonator lasting access to the account
	 * (app passwords, URL signing key, OAuth2 grants) are refused.
	 */
	public function isForbiddenRequest(): bool {
		if (!$this->util->isImpersonating()) {
			return false;
		}
		$method = \strtoupper($this->request->getMethod());
		foreach (self::candidatePaths($this->request) as $path) {
			foreach (self::FORBIDDEN as [$forbiddenMethod, $forbiddenPath]) {
				if ($path === $forbiddenPath && ($forbiddenMethod === '*' || $forbiddenMethod === $method)) {
					return true;
				}
			}
			foreach (self::FORBIDDEN_PREFIXES as $prefix) {
				if (\strpos($path . '/', $prefix) === 0) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * The request path as the router matches it: raw path info with repeated
	 * slashes collapsed, URL decoded, without trailing slash.
	 */
	public static function normalizedPath(IRequest $request): string {
		$paths = self::candidatePaths($request);
		return $paths[0] ?? '';
	}

	/**
	 * @return string[] normalized variants of the request path (raw and decoded path info)
	 */
	private static function candidatePaths(IRequest $request): array {
		$paths = [];
		foreach (['getRawPathInfo', 'getPathInfo'] as $getter) {
			try {
				$path = $request->$getter();
			} catch (\Exception $e) {
				continue;
			}
			if (!\is_string($path) || $path === '') {
				continue;
			}
			$path = \rawurldecode((string)\preg_replace('%/{2,}%', '/', $path));
			$path = (string)\preg_replace('%/{2,}%', '/', $path);
			$path = \rtrim($path, '/');
			$paths[] = $path === '' ? '/' : $path;
		}
		return \array_values(\array_unique($paths));
	}

	/**
	 * Answer a forbidden request with HTTP 403 and stop processing it.
	 *
	 * @codeCoverageIgnore
	 */
	public function denyRequest(): void {
		$this->logger->warning(
			'Refused {method} {path} for user "{target}" while "{impersonator}" impersonates them',
			[
				'app' => 'impersonate',
				'target' => $this->userSession->getUser() !== null ? $this->userSession->getUser()->getUID() : '',
				'impersonator' => $this->util->getImpersonatorUid(),
				'method' => $this->request->getMethod(),
				'path' => self::normalizedPath($this->request),
			]
		);
		while (\ob_get_level() > 0) {
			\ob_end_clean();
		}
		\http_response_code(403);
		\header('Content-Type: application/json; charset=utf-8');
		echo \json_encode(['message' => 'This action is not allowed while impersonating a user']);
		exit();
	}
}
