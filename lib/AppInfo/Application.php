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

namespace OCA\Impersonate\AppInfo;

use OC\Authentication\Token\DefaultTokenProvider;
use OCA\Impersonate\ActiveImpersonations;
use OCA\Impersonate\AuditTrail;
use OCA\Impersonate\Command\Active;
use OCA\Impersonate\CredentialCleanup;
use OCA\Impersonate\ImpersonationGuard;
use OCA\Impersonate\LogoutListener;
use OCA\Impersonate\Policy;
use OCA\Impersonate\Reconciler;
use OCA\Impersonate\Util;
use OCP\AppFramework\App;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

class Application extends App {
	public function __construct(array $urlParams = []) {
		parent::__construct('impersonate', $urlParams);
		$container = $this->getContainer();
		$server = $container->getServer();

		$container->registerService(Policy::class, function () use ($server) {
			$groupManager = $server->getGroupManager();
			if (!$groupManager instanceof \OC\Group\Manager) {
				throw new \LogicException('Unsupported group manager implementation');
			}
			return new Policy(
				$server->getConfig(),
				$groupManager,
				$groupManager->getSubAdmin(),
				$server->getDatabaseConnection(),
				$server->getLogger()
			);
		});
		$container->registerService(EventDispatcherInterface::class, function () use ($server) {
			return $server->getEventDispatcher();
		});
		$container->registerService(DefaultTokenProvider::class, function () use ($server) {
			return $server->query(DefaultTokenProvider::class);
		});
		$container->registerService(AuditTrail::class, function () use ($server) {
			return new AuditTrail(
				$server->getEventDispatcher(),
				$server->getNotificationManager(),
				$server->getLogger()
			);
		});
		$container->registerService(ActiveImpersonations::class, function () use ($server) {
			return new ActiveImpersonations(
				$server->getConfig(),
				$server->getSecureRandom(),
				$server->getJobList(),
				$server->getDatabaseConnection(),
				$server->getLogger()
			);
		});
		$container->registerService(CredentialCleanup::class, function ($c) use ($server) {
			return new CredentialCleanup(
				$c->query(DefaultTokenProvider::class),
				$server->getConfig(),
				$c->query(AuditTrail::class),
				$server->getLogger()
			);
		});
		$container->registerService(Util::class, function ($c) use ($server) {
			/** @var \OC\User\Session $userSession */
			$userSession = $server->getUserSession();
			/** @var \OC\Security\CSRF\CsrfTokenManager $csrfTokenManager */
			$csrfTokenManager = \OC::$server->getCsrfTokenManager();
			return new Util(
				$server->getSession(),
				$userSession,
				$c->query(DefaultTokenProvider::class),
				$server->getUserManager(),
				$server->getSecureRandom(),
				$csrfTokenManager,
				$server->getLogger(),
				$server->getConfig(),
				$c->query(ActiveImpersonations::class),
				$c->query(CredentialCleanup::class),
				$c->query(AuditTrail::class),
				$c->query(Policy::class)
			);
		});
		$container->registerService(LogoutListener::class, function ($c) use ($server) {
			return new LogoutListener(
				$c->query(Util::class),
				$server->getUserSession(),
				$server->getRequest(),
				$server->getLogger()
			);
		});
		$container->registerService(ImpersonationGuard::class, function ($c) use ($server) {
			return new ImpersonationGuard(
				$c->query(Util::class),
				$c->query(Policy::class),
				$server->getUserSession(),
				$server->getUserManager(),
				$server->getRequest(),
				$server->getLogger(),
				$c->query(ActiveImpersonations::class),
				$c->query(CredentialCleanup::class),
				$c->query(Reconciler::class)
			);
		});
		$container->registerService(Reconciler::class, function ($c) use ($server) {
			return new Reconciler(
				$c->query(ActiveImpersonations::class),
				$c->query(CredentialCleanup::class),
				$c->query(Policy::class),
				$server->getUserManager(),
				$c->query(AuditTrail::class),
				$server->getLogger()
			);
		});
		$container->registerService(Active::class, function ($c) use ($server) {
			return new Active($c->query(Reconciler::class), $server->getConfig());
		});
	}
}
