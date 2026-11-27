<?php
/**
 * Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
 * Original author: Marek Królikowski (TaKeN)
 * Original project: https://github.com/takenek/impersonate
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE and COPYRIGHT for the license and the AGPL section 7 attribution terms.
 */

// occ commands of the app; $application is the console application of occ (the variable that
// OC\Console\Application::loadCommands() provides to this file).
// An error here must not take occ down with it (app:disable has to stay possible).
try {
	/** @var \Symfony\Component\Console\Application|null $application */
	$console = $application ?? null;
	if (!$console instanceof \Symfony\Component\Console\Application) {
		throw new \UnexpectedValueException('occ did not provide its console application');
	}
	$impersonate = new \OCA\Impersonate\AppInfo\Application();
	$command = $impersonate->getContainer()->query(\OCA\Impersonate\Command\Active::class);
	// addCommand(): add() is deprecated since Symfony Console 7.4 (every ownCloud 11 release ships
	// 7.4) and removed in Symfony 8
	$console->addCommand($command);
} catch (\Throwable $e) {
	\OC::$server->getLogger()->logException($e, ['app' => 'impersonate']);
}
