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

use OCA\Impersonate\ImpersonationGuard;
use OCA\Impersonate\LogoutListener;
use OCA\Impersonate\Policy;
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
				$groupManager->getSubAdmin()
			);
		});
		$container->registerService(EventDispatcherInterface::class, function () use ($server) {
			return $server->getEventDispatcher();
		});
		$container->registerService(Util::class, function () {
			return Util::fromServer();
		});
		$container->registerService(LogoutListener::class, function ($c) use ($server) {
			return new LogoutListener(
				$c->query(Util::class),
				$server->getUserSession(),
				$server->getRequest(),
				$server->getEventDispatcher(),
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
				$server->getLogger()
			);
		});
	}
}
