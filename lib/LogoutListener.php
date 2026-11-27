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
use OCP\IUserSession;
use Symfony\Component\EventDispatcher\GenericEvent;

/**
 * Listener for '\OC\User\Session::pre_logout'.
 *
 * When an impersonated session is logged out by the user (core route
 * GET /logout with a valid CSRF token, while the impersonated session is still
 * valid), the logout is cancelled and the session is switched back to the
 * impersonator. Every other logout (session revoked, token invalid,
 * user disabled, auth header mismatch, password reset, ...) is a security
 * logout: the impersonation is ended and the logout proceeds.
 *
 * The end event is dispatched by Util for every way an impersonation ends.
 */
class LogoutListener {
	/** @var Util */
	private $util;
	/** @var IUserSession */
	private $userSession;
	/** @var IRequest */
	private $request;
	/** @var ILogger */
	private $logger;

	public function __construct(
		Util $util,
		IUserSession $userSession,
		IRequest $request,
		ILogger $logger
	) {
		$this->util = $util;
		$this->userSession = $userSession;
		$this->request = $request;
		$this->logger = $logger;
	}

	public function onPreLogout(GenericEvent $event): void {
		$impersonator = $this->util->getImpersonatorUid();
		// core also dispatches this event a second time without the 'cancel'
		// argument; only the cancellable dispatch is handled
		if ($impersonator === null || !$event->hasArgument('cancel')) {
			return;
		}
		$target = $this->util->getTargetUid();
		if ($target === null) {
			$currentUser = $this->userSession->getUser();
			$target = $currentUser !== null ? $currentUser->getUID() : '';
		}
		$remote = $this->request->getRemoteAddress();

		if ($this->isUserInitiatedLogout() && $this->util->stopImpersonation()) {
			$event->setArgument('cancel', true);
			$this->logger->warning(
				'User "{impersonator}" stopped impersonating user "{target}" (from {remote})',
				['app' => 'impersonate', 'impersonator' => $impersonator, 'target' => $target, 'remote' => $remote]
			);
		} else {
			// stopImpersonation() already ended the impersonation if it failed
			$this->util->endImpersonation(Util::REASON_LOGOUT);
			$this->logger->warning(
				'Impersonation of user "{target}" by "{impersonator}" ended by a logout of the session (from {remote})',
				['app' => 'impersonate', 'impersonator' => $impersonator, 'target' => $target, 'remote' => $remote]
			);
		}
	}

	/**
	 * Is this the user clicking "Log out" (core route core.login.logout, which
	 * carries the CSRF token)? A logout that core triggers while validating the
	 * session can happen on any URL, including GET /logout without a valid token.
	 */
	private function isUserInitiatedLogout(): bool {
		if ($this->request->getMethod() !== 'GET') {
			return false;
		}
		$path = ImpersonationGuard::normalizedPath($this->request);
		return $path === '/logout' && $this->request->passesCSRFCheck();
	}
}
