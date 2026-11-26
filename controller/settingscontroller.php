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
 * ownCloud - impersonate
 *
 * This file is licensed under the Affero General Public License version 3 or
 * later. See the COPYING file.
 *
 * @author Jörn Friedrich Dreyer <jfd@owncloud.com>
 * @copyright Jörn Friedrich Dreyer 2015
 */

namespace OCA\Impersonate\Controller;

use OCA\Impersonate\Policy;
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
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\EventDispatcher\GenericEvent;

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
	/** @var EventDispatcherInterface */
	private $eventDispatcher;

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
		EventDispatcherInterface $eventDispatcher
	) {
		parent::__construct($appName, $request);
		$this->userManager = $userManager;
		$this->userSession = $userSession;
		$this->logger = $logger;
		$this->config = $config;
		$this->l = $l10n;
		$this->policy = $policy;
		$this->util = $util;
		$this->eventDispatcher = $eventDispatcher;
	}

	/**
	 * Data the users page needs to decide where to show the impersonate icon:
	 * [included groups (JSON), include groups mode, all group admins mode, isAdmin, isGroupAdmin,
	 *  admins within the group admin's groups (JSON)]
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
		if ($this->policy->isDelegatedGroupAdmin($currentUser)) {
			$groups = $this->policy->getImpersonableGroupIds($currentUser);
			return new JSONResponse([
				\json_encode($groups),
				$this->policy->isIncludeGroupsMode() ? 'true' : 'false',
				$this->policy->isAllGroupAdminsMode() ? 'true' : 'false',
				false,
				true,
				\json_encode($this->policy->getAdminUidsInGroups($groups)),
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
		if ($this->config->getAppValue('impersonate', 'enabled', 'no') === 'no') {
			$this->logger->warning('Impersonation refused: the app is not enabled', ['app' => 'impersonate']);
			return $this->error(
				Policy::ERROR_CANNOT_IMPERSONATE,
				$this->l->t('Can not impersonate. Please contact your server administrator to allow impersonation.')
			);
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

		// Decide whether the user may impersonate at all before looking at the
		// target, so that nothing about other accounts is revealed.
		if (!$this->policy->mayImpersonateAnyone($currentUser)) {
			$this->logger->warning(
				'User "{impersonator}" is not allowed to impersonate users',
				['app' => 'impersonate', 'impersonator' => $impersonator]
			);
			return $this->error(Policy::ERROR_CANNOT_IMPERSONATE, $this->l->t('Can not impersonate'));
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
		} catch (\Exception $e) {
			$this->logger->logException($e, ['app' => 'impersonate']);
			return $this->error(Policy::ERROR_CANNOT_IMPERSONATE, $this->l->t('Can not impersonate'));
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
		$startEvent = new GenericEvent(null, ['impersonator' => $impersonator, 'targetUser' => $targetUid]);
		$this->eventDispatcher->dispatch($startEvent, 'user.afterimpersonate');
		return new JSONResponse();
	}

	private function error(string $code, string $message): JSONResponse {
		return new JSONResponse(['error' => $code, 'message' => $message], Http::STATUS_NOT_FOUND);
	}
}
