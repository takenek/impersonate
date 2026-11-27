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

namespace OCA\Impersonate\Command;

use OCA\Impersonate\Reconciler;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * occ impersonate:active [--end]
 *
 * Lists the impersonations that are active. With --end every one of them is
 * ended: its session is revoked and the credential cleanup runs. Use it
 * before the app is disabled (a session that impersonates when the app is
 * disabled would keep the impersonated identity without any of the app's
 * controls) and when an impersonation has to be stopped at once.
 */
class Active extends Command {
	/** @var Reconciler */
	private $reconciler;

	public function __construct(Reconciler $reconciler) {
		parent::__construct();
		$this->reconciler = $reconciler;
	}

	protected function configure(): void {
		$this
			->setName('impersonate:active')
			->setDescription('List the active impersonations, or end all of them (--end).')
			->addOption('end', null, InputOption::VALUE_NONE, 'End every active impersonation: revoke its session and clean up.');
	}

	protected function execute(InputInterface $input, OutputInterface $output): int {
		// first finish what is over anyway, so that the list shows what is really active
		$this->reconciler->run();
		$active = $this->reconciler->getActive();
		if ($active === []) {
			$output->writeln('No active impersonations.');
			if ($input->getOption('end')) {
				$this->finishEnd($output);
			}
			return 0;
		}
		foreach ($active as $record) {
			$output->writeln(\sprintf(
				'%s impersonates %s since %s',
				$record['impersonator'],
				$record['target'],
				\date('c', $record['start'])
			));
		}
		if (!$input->getOption('end')) {
			return 0;
		}
		$ended = $this->reconciler->run(true);
		$output->writeln(\sprintf('Ended %d impersonation(s).', $ended));
		$this->finishEnd($output);
		return $ended === \count($active) ? 0 : 1;
	}

	/**
	 * With nothing left to do the background job of the app is taken off the
	 * job list, so that the app can be disabled without leaving a job behind.
	 */
	private function finishEnd(OutputInterface $output): void {
		$pending = $this->reconciler->countPending();
		if ($pending > 0) {
			$output->writeln(\sprintf(
				'The cleanup after %d impersonation(s) is not complete yet (see the ownCloud log); the background job retries it.',
				$pending
			));
		}
		$this->reconciler->releaseJobIfIdle();
	}
}
