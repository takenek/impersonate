<?php
/**
 * Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
 * Original author: Marek Królikowski (TaKeN)
 * Original project: https://github.com/takenek/impersonate
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE and COPYRIGHT for the license and the AGPL section 7 attribution terms.
 */

// occ commands of the app; $application is the console application of occ.
// An error here must not take occ down with it (app:disable has to stay possible).
try {
	$impersonate = new \OCA\Impersonate\AppInfo\Application();
	/** @var \Symfony\Component\Console\Application $application */
	// @phan-suppress-next-line PhanUndeclaredGlobalVariable
	$application->add($impersonate->getContainer()->query(\OCA\Impersonate\Command\Active::class));
} catch (\Throwable $e) {
	\OC::$server->getLogger()->logException($e, ['app' => 'impersonate']);
}
