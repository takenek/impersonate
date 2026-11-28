<?php
/**
 * Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
 * Maintained by Marek Królikowski (TaKeN): https://github.com/takenek/impersonate
 * Modified on 2026-11-26, 2026-11-27 and 2026-11-28 by Marek Królikowski (TaKeN): ownCloud 11.1
 * support and security hardening, see CHANGELOG.md. SPDX-License-Identifier: AGPL-3.0-only
 * See LICENSE and COPYRIGHT.
 *
 * Based on the ownCloud "impersonate" app (https://github.com/owncloud/impersonate):
 *
 * ownCloud - impersonate
 *
 * This file is licensed under the Affero General Public License version 3 or
 * later. See the COPYING file.
 *
 * @author Jörn Friedrich Dreyer <jfd@owncloud.com>
 * @copyright Jörn Friedrich Dreyer 2015
 */

namespace OCA\Impersonate\Controller;

use OCA\Impersonate\AuditTrail;
use OCA\Impersonate\ImpersonationGuard;
use OCA\Impersonate\Policy;
use OCA\Impersonate\RefusedException;
use OCA\Impersonate\Util;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\JSONResponse;
use OCP\IConfig;
use OCP\IL10N;
use OCP\ILogger;
use OCP\IRequest;
use OCP\IUserManager;
use OCP\IUserSession;

class SettingsController extends Controller {
	/** @var IUserManager */
	private $userManager;
	/** @var IUserSession */
	private $userSession;
	/** @var ILogger */
	private $logger;
	/** @var IConfig */
	private $config;
	/** @var IL10N */
	private $l;
	/** @var Policy */
	private $policy;
	/** @var Util */
	private $util;
	/** @var AuditTrail */
	private $auditTrail;
	/** @var ImpersonationGuard */
	private $guard;

	public function __construct(
		$appName,
		IRequest $request,
		IUserManager $userManager,
		IUserSession $userSession,
		ILogger $logger,
		IConfig $config,
		IL10N $l10n,
		Policy $policy,
		Util $util,
		AuditTrail $auditTrail,
		ImpersonationGuard $guard
	) {
		parent::__construct($appName, $request);
		$this->userManager = $userManager;
		$this->userSession = $userSession;
		$this->logger = $logger;
		$this->config = $config;
		$this->l = $l10n;
		$this->policy = $policy;
		$this->util = $util;
		$this->auditTrail = $auditTrail;
		$this->guard = $guard;
	}

	/**
	 * Data the users page needs to decide where to show the impersonate icon:
	 * [included groups (JSON), include groups mode, all group admins mode, isAdmin, isGroupAdmin,
	 *  members of the group admin's groups the group admin can not impersonate (JSON): administrators
	 *  and - unless such targets are allowed - group admins]
	 * The delegation policy is only revealed to users who can impersonate.
	 *
	 * @NoAdminRequired
	 *
	 * @return JSONResponse
	 */
	public function getDataForImpersonateApp() {
		$currentUser = $this->userSession->getUser();
		if ($currentUser === null || $this->util->isImpersonating()) {
			return new JSONResponse(['[]', 'false', 'false', false, false, '[]']);
		}
		if ($this->policy->isAdmin($currentUser)) {
			return new JSONResponse([
				\json_encode($this->policy->getIncludedGroups()),
				$this->policy->isIncludeGroupsMode() ? 'true' : 'false',
				$this->policy->isAllGroupAdminsMode() ? 'true' : 'false',
				true,
				false,
				'[]',
			]);
		}
		// a group admin none of whose groups is delegated can not impersonate anybody: the empty answer
		$groups = $this->policy->isDelegatedGroupAdmin($currentUser) ? $this->policy->getImpersonableGroupIds($currentUser) : [];
		if ($groups !== []) {
			return new JSONResponse([
				\json_encode($groups),
				$this->policy->isIncludeGroupsMode() ? 'true' : 'false',
				$this->policy->isAllGroupAdminsMode() ? 'true' : 'false',
				false,
				true,
				\json_encode(\array_values(\array_diff(
					\array_unique(\array_merge(
						$this->policy->getAdminUidsInGroups($groups),
						$this->policy->getGroupAdminUidsInGroups($groups)
					)),
					// that the user can not impersonate themselves needs no entry
					[$currentUser->getUID()]
				))),
			]);
		}
		return new JSONResponse(['[]', 'false', 'false', false, false, '[]']);
	}

	/**
	 * become another user
	 *
	 * @UseSession
	 * @NoAdminRequired
	 *
	 * @param string $target
	 * @return JSONResponse
	 */
	public function impersonate($target) {
		// The checks of the app run for every request only if the app is loaded for every request:
		// an app that is enabled for some groups only would not be loaded for the session of an
		// impersonated user outside those groups.
		$enabled = $this->config->getAppValue('impersonate', 'enabled', 'no');
		if ($enabled !== 'yes') {
			$this->logger->warning(
				$enabled === 'no'
					? 'Impersonation refused: the app is not enabled'
					: 'Impersonation refused: the app is not enabled for everybody (it must not be limited to groups)',
				['app' => 'impersonate']
			);
			return $this->error(
				Policy::ERROR_CANNOT_IMPERSONATE,
				$this->l->t('Can not impersonate. Please contact your server administrator to allow impersonation.')
			);
		}
		// No impersonation without the guard (ImpersonationGuard::onLoadedApps()) that checks every
		// request of it: if it did not see this request, it will not see the next ones either.
		if (!$this->guard->isActiveForThisRequest()) {
			$this->logger->error(
				'Impersonation refused: the request guard of the app is not active (see the ownCloud log for the cause)',
				['app' => 'impersonate']
			);
			return $this->error(Policy::ERROR_CANNOT_IMPERSONATE, $this->l->t('Can not impersonate'));
		}

		$currentUser = $this->userSession->getUser();
		if ($currentUser === null) {
			return $this->error(Policy::ERROR_CANNOT_IMPERSONATE, $this->l->t('Can not impersonate'));
		}
		$impersonator = $currentUser->getUID();

		if ($this->util->isImpersonating()) {
			$this->logger->warning(
				'Refused a nested impersonation in the session of "{impersonator}" impersonated by "{original}"',
				[
					'app' => 'impersonate',
					'impersonator' => $impersonator,
					'original' => $this->util->getImpersonatorUid(),
				]
			);
			return $this->error('stopNestedImpersonation', $this->l->t('Can not impersonate'));
		}

		// An impersonation starts from the browser session of the impersonator and from
		// nothing else: a request that brings its own credentials (HTTP Basic, a token) is
		// not one, even if the platform gave it a session. Such requests do not need the
		// CSRF token either, so they must not be able to switch a session.
		if (!$this->policy->allowsStartWithCredentials() && $this->requestCarriesCredentials()) {
			$this->logger->warning(
				'Impersonation by "{impersonator}" refused: an impersonation must be started from an interactive session (the request carries credentials)',
				['app' => 'impersonate', 'impersonator' => $impersonator]
			);
			return $this->error(Policy::ERROR_CANNOT_IMPERSONATE, $this->l->t('Can not impersonate'));
		}

		// Whatever authenticated the request: the start is a deliberate action in the user
		// interface, which always sends the CSRF token. The platform does not ask a request that
		// carries credentials for it, which allow_start_with_credentials lets through above.
		if (!$this->request->passesCSRFCheck()) {
			$this->logger->warning(
				'Impersonation by "{impersonator}" refused: the request has no valid CSRF token',
				['app' => 'impersonate', 'impersonator' => $impersonator]
			);
			return $this->error(Policy::ERROR_CANNOT_IMPERSONATE, $this->l->t('Can not impersonate'));
		}

		// Decide whether the user may impersonate at all before looking at the
		// target, so that nothing about other accounts is revealed.
		if (!$this->policy->mayImpersonateAnyone($currentUser)) {
			$this->logger->warning(
				'User "{impersonator}" is not allowed to impersonate users',
				['app' => 'impersonate', 'impersonator' => $impersonator]
			);
			return $this->error(Policy::ERROR_CANNOT_IMPERSONATE, $this->l->t('Can not impersonate'));
		}
		// new impersonations are blocked for a maintenance window (occ impersonate:active --block);
		// told only to users who may impersonate
		try {
			$blocked = $this->util->areStartsBlocked();
		} catch (\Throwable $e) {
			$this->logger->logException($e, ['app' => 'impersonate']);
			return $this->error(Policy::ERROR_CANNOT_IMPERSONATE, $this->l->t('Can not impersonate'));
		}
		if ($blocked) {
			$this->logger->warning(
				'Impersonation by "{impersonator}" refused: new impersonations are blocked (occ impersonate:active --unblock)',
				['app' => 'impersonate', 'impersonator' => $impersonator]
			);
			return $this->error(
				Policy::ERROR_CANNOT_IMPERSONATE,
				$this->l->t('Can not impersonate. Please contact your server administrator to allow impersonation.')
			);
		}

		$isAdmin = $this->policy->isAdmin($currentUser);

		$user = \is_string($target) && $target !== '' ? $this->userManager->get($target) : null;
		if ($user === null) {
			$this->logger->warning(
				'User "{impersonator}" tried to impersonate a user that does not exist',
				['app' => 'impersonate', 'impersonator' => $impersonator]
			);
			return $isAdmin
				? $this->error('userNotFound', $this->l->t('Unexpected error occurred'))
				: $this->error(Policy::ERROR_CANNOT_IMPERSONATE, $this->l->t('Can not impersonate'));
		}
		$targetUid = $user->getUID();

		$denied = $this->policy->check($currentUser, $user);
		if ($denied !== null) {
			$this->logger->warning(
				'User "{impersonator}" is not allowed to impersonate user "{target}" ({reason})',
				['app' => 'impersonate', 'impersonator' => $impersonator, 'target' => $targetUid, 'reason' => $denied]
			);
			if ($denied === Policy::ERROR_DISABLED_TARGET && $isAdmin) {
				return $this->error($denied, $this->l->t('Can not impersonate a disabled user'));
			}
			// group admins get a generic error that does not reveal details about the account
			return $this->error(Policy::ERROR_CANNOT_IMPERSONATE, $this->l->t('Can not impersonate'));
		}

		if ($user->getLastLogin() === 0) {
			// the file system of a user can only be set up after a proper login
			$this->logger->warning(
				'User "{target}" has not logged in yet. User "{impersonator}" cannot impersonate them',
				['app' => 'impersonate', 'impersonator' => $impersonator, 'target' => $targetUid]
			);
			return $this->error(
				Policy::ERROR_NEVER_LOGGED_IN,
				$this->l->t('Can not impersonate a user who has never logged in')
			);
		}

		try {
			$this->util->startImpersonation($user, $currentUser);
		} catch (RefusedException $e) {
			// nothing was changed, e.g. a request authenticated with HTTP Basic credentials
			$this->logger->warning(
				'Impersonation of user "{target}" by "{impersonator}" refused: {reason}',
				['app' => 'impersonate', 'impersonator' => $impersonator, 'target' => $targetUid, 'reason' => $e->getMessage()]
			);
			return $this->error(Policy::ERROR_CANNOT_IMPERSONATE, $this->l->t('Can not impersonate'));
		} catch (\Throwable $e) {
			// The switch failed: the session may have been logged out (Util rolls a partial
			// switch back). Not the answer of a refusal: the browser must not offer a retry
			// on a page whose session may be gone.
			$this->logger->logException($e, ['app' => 'impersonate']);
			return new JSONResponse(
				['error' => 'switchFailed', 'message' => $this->l->t('Can not impersonate')],
				Http::STATUS_INTERNAL_SERVER_ERROR
			);
		}

		$this->logger->warning(
			'User "{impersonator}" started impersonating user "{target}" (from {remote})',
			[
				'app' => 'impersonate',
				'impersonator' => $impersonator,
				'target' => $targetUid,
				'remote' => $this->request->getRemoteAddress(),
			]
		);
		// the switch has happened: a failing event consumer does not change the answer
		$this->auditTrail->started($impersonator, $targetUid, $this->util->getRecordId());
		return new JSONResponse();
	}

	/**
	 * Store the delegation policy as a whole (administrators only: no
	 * NoAdminRequired annotation; the CSRF token is required).
	 * The answer is the policy the server applies from now on.
	 *
	 * The parameters are request values as they come (no type is declared, so
	 * the framework does not cast them), they are validated here.
	 *
	 * @param mixed $mode Policy::MODE_*
	 * @param mixed $groups list of group ids for Policy::MODE_INCLUDE_GROUPS
	 * @param mixed $allowGroupAdminTargets true (or the string "true"): group admins may
	 *                                      impersonate members who are group admins;
	 *                                      anything else: they may not
	 * @return JSONResponse
	 */
	public function setPolicy($mode, $groups = [], $allowGroupAdminTargets = false) {
		$currentUser = $this->userSession->getUser();
		// not left to the framework alone: the policy decides who can take over which account
		if ($currentUser === null || !$this->policy->isAdmin($currentUser) || $this->util->isImpersonating()) {
			return new JSONResponse(['error' => 'forbidden'], Http::STATUS_FORBIDDEN);
		}
		if (!\is_string($mode) || !\is_array($groups)) {
			return new JSONResponse(['error' => 'invalidPolicy', 'policy' => $this->policy->describe()], Http::STATUS_BAD_REQUEST);
		}
		try {
			$stored = $this->policy->store(
				$mode,
				$groups,
				$allowGroupAdminTargets === true || $allowGroupAdminTargets === 'true'
			);
		} catch (\InvalidArgumentException $e) {
			return new JSONResponse(['error' => 'invalidPolicy', 'policy' => $this->policy->describe()], Http::STATUS_BAD_REQUEST);
		} catch (\Throwable $e) {
			$this->logger->logException($e, ['app' => 'impersonate']);
			return new JSONResponse(['error' => 'notSaved'], Http::STATUS_INTERNAL_SERVER_ERROR);
		}
		$this->logger->warning(
			'User "{admin}" set the impersonation policy to {mode} (groups: {groups}; group admins as targets: {targets})',
			[
				'app' => 'impersonate',
				'admin' => $currentUser->getUID(),
				'mode' => $stored['mode'],
				'groups' => \json_encode($stored['groups']),
				'targets' => $stored['allowGroupAdminTargets'] ? 'allowed' : 'not allowed',
			]
		);
		return new JSONResponse(['policy' => $stored]);
	}

	/**
	 * Does the request authenticate itself (HTTP Basic, a token) instead of
	 * relying on the session cookie?
	 */
	private function requestCarriesCredentials(): bool {
		foreach ([
			$this->request->getHeader('Authorization'),
			$_SERVER['PHP_AUTH_USER'] ?? null,
			$_SERVER['PHP_AUTH_PW'] ?? null,
			$_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? null,
		] as $value) {
			if (\is_string($value) && \trim($value) !== '') {
				return true;
			}
		}
		return false;
	}

	private function error(string $code, string $message): JSONResponse {
		return new JSONResponse(['error' => $code, 'message' => $message], Http::STATUS_NOT_FOUND);
	}
}
