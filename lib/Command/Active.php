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

use OCA\Impersonate\ActiveImpersonations;
use OCA\Impersonate\Reconciler;
use OCP\IConfig;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * occ impersonate:active [--end] [--block | --unblock]
 *
 * Lists the impersonations that are active. With --end every one of them is
 * ended: its session is revoked and the credential cleanup runs. Use it
 * before the app is disabled or its folder is replaced (a session that
 * impersonates while the app is not loaded keeps the impersonated identity
 * without any of the app's controls) and when an impersonation has to be
 * stopped at once. --block (first) keeps new impersonations from starting
 * until --unblock, so that none starts between the end and the maintenance.
 *
 * Exit status: 0 when nothing is active (and, with --end, nothing waits for its
 * cleanup); with --end 1 while an impersonation is still active, 3 when every
 * impersonation has ended but a cleanup - possibly the revocation of a session
 * token - is still open (the background job retries it); 2 for --block
 * together with --unblock.
 */
class Active extends Command {
	/** with --end: an impersonation is still active */
	public const EXIT_ACTIVE = 1;
	/** --block together with --unblock */
	public const EXIT_INVALID = 2;
	/** with --end: every impersonation has ended, but a cleanup is still open */
	public const EXIT_PENDING = 3;

	/** @var Reconciler */
	private $reconciler;
	/** @var IConfig */
	private $config;

	public function __construct(Reconciler $reconciler, IConfig $config) {
		parent::__construct();
		$this->reconciler = $reconciler;
		$this->config = $config;
	}

	protected function configure(): void {
		$this
			->setName('impersonate:active')
			->setDescription('List the active impersonations, or end all of them (--end).')
			->addOption(
				'end',
				null,
				InputOption::VALUE_NONE,
				'End every active impersonation: revoke its session and clean up. Exit status 0 only if nothing is active or waiting for its cleanup afterwards.'
			)
			->addOption('block', null, InputOption::VALUE_NONE, 'Block new impersonations until --unblock (first, before anything else).')
			->addOption('unblock', null, InputOption::VALUE_NONE, 'Allow new impersonations again.');
	}

	protected function execute(InputInterface $input, OutputInterface $output): int {
		$block = (bool)$input->getOption('block');
		$unblock = (bool)$input->getOption('unblock');
		if ($block && $unblock) {
			$output->writeln('<error>--block and --unblock can not be combined.</error>');
			return self::EXIT_INVALID;
		}
		if ($block || $unblock) {
			$this->reconciler->blockStarts($block);
			$output->writeln($block
				? 'New impersonations are blocked until occ impersonate:active --unblock.'
				: 'New impersonations are allowed again.');
		} elseif ($this->reconciler->startsBlocked()) {
			$output->writeln('New impersonations are blocked (occ impersonate:active --unblock).');
		}
		$enabled = $this->config->getAppValue('impersonate', 'enabled', 'no');
		if ($enabled !== 'yes') {
			$output->writeln(\sprintf(
				'Warning: the app is not enabled for everybody ("enabled" is %s): impersonations can not be started. Enable it with occ app:enable impersonate.',
				\json_encode($enabled)
			));
		}

		// first finish what is over anyway, so that the list shows what is really active
		$this->reconciler->run();
		$active = $this->reconciler->getActive();
		if ($active === []) {
			$output->writeln('No active impersonations.');
		}
		$this->listActive($output, $active);
		if (!$input->getOption('end')) {
			$this->reportPending($output);
			return 0;
		}

		if ($active !== []) {
			$ended = $this->reconciler->run(true);
			$output->writeln(\sprintf('Ended %d impersonation(s).', $ended));
		}
		// what counts is what is active now, whatever was listed before
		$left = $this->reconciler->getActive();
		if ($left !== []) {
			$output->writeln(\sprintf('%d impersonation(s) could not be ended:', \count($left)));
			$this->listActive($output, $left);
		}
		$pending = $this->reportPending($output);
		if (!$block && !$this->reconciler->startsBlocked()) {
			$output->writeln('New impersonations can still be started: --block prevents that until --unblock.');
		}
		// with nothing left to do the background job is taken off the job list, so that the app
		// can be disabled without leaving a job behind
		$this->reconciler->releaseJobIfIdle();
		if ($left !== []) {
			return self::EXIT_ACTIVE;
		}
		return $pending > 0 ? self::EXIT_PENDING : 0;
	}

	/**
	 * @param array<string, array<string, mixed>> $records
	 */
	private function listActive(OutputInterface $output, array $records): void {
		foreach ($records as $record) {
			$output->writeln(\sprintf(
				'%s impersonates %s since %s',
				$record['impersonator'],
				$record['target'],
				\date('c', $record['start'])
			));
		}
	}

	/**
	 * The impersonations whose cleanup is not complete, each with what an operator needs to decide
	 * about it (its record, see README section 2).
	 *
	 * @return int number of impersonations whose cleanup is not complete
	 */
	private function reportPending(OutputInterface $output): int {
		$pending = $this->reconciler->getPending();
		if ($pending === []) {
			return 0;
		}
		$output->writeln(\sprintf(
			'The cleanup after %d impersonation(s) is not complete yet (see the ownCloud log); the background job retries it.',
			\count($pending)
		));
		$unrevoked = \count(\array_filter($pending, [ActiveImpersonations::class, 'namesCredential']));
		if ($unrevoked > 0) {
			$output->writeln(\sprintf(
				'The session token of %d of them is not known to be revoked yet: such a session may still be valid.',
				$unrevoked
			));
		}
		foreach ($pending as $id => $record) {
			$output->writeln(\sprintf(
				'  record active_%s: %s impersonated %s, ended %s, session token %s',
				$id,
				$record['impersonator'],
				$record['target'],
				\date('c', $record['ended']),
				ActiveImpersonations::namesCredential($record) ? 'not known to be revoked' : 'revoked'
			));
		}
		return \count($pending);
	}
}
