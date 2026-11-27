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

namespace OCA\Impersonate\BackgroundJob;

use OC\BackgroundJob\TimedJob;
use OCA\Impersonate\AppInfo\Application;
use OCA\Impersonate\Reconciler;

/**
 * Ends and cleans up impersonations whose session is gone (see Reconciler).
 * Registered when an impersonation starts (ActiveImpersonations::open()).
 */
class Reconcile extends TimedJob {
	public function __construct() {
		// at most every five minutes; how often it really runs depends on the cron setup of the instance
		$this->setInterval(300);
	}

	/**
	 * @param mixed $argument
	 */
	protected function run($argument) {
		try {
			$application = new Application();
			/** @var Reconciler $reconciler */
			$reconciler = $application->getContainer()->query(Reconciler::class);
			$reconciler->run();
		} catch (\Throwable $e) {
			\OC::$server->getLogger()->logException($e, ['app' => 'impersonate']);
		}
	}
}
