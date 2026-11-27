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
use OCP\Notification\IManager;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\EventDispatcher\GenericEvent;

/**
 * The one place that tells other apps (audit, notifications) what happened:
 *
 * - user.afterimpersonate                  an impersonation started
 * - user.afterimpersonatelogout            an impersonation ended, with the reason
 * - user.impersonate.credentialrevoked     the cleanup revoked a credential of the impersonated user
 *
 * A failing consumer must never change the outcome of the switch that already
 * happened, so every dispatch is isolated.
 */
class AuditTrail {
	public const EVENT_START = 'user.afterimpersonate';
	public const EVENT_END = 'user.afterimpersonatelogout';
	public const EVENT_CREDENTIAL_REVOKED = 'user.impersonate.credentialrevoked';

	/** @var EventDispatcherInterface */
	private $eventDispatcher;
	/** @var IManager */
	private $notificationManager;
	/** @var ILogger */
	private $logger;

	public function __construct(EventDispatcherInterface $eventDispatcher, IManager $notificationManager, ILogger $logger) {
		$this->eventDispatcher = $eventDispatcher;
		$this->notificationManager = $notificationManager;
		$this->logger = $logger;
	}

	public function started(string $impersonatorUid, string $targetUid): void {
		$this->dispatch(self::EVENT_START, ['impersonator' => $impersonatorUid, 'targetUser' => $targetUid]);
	}

	public function ended(string $impersonatorUid, string $targetUid, string $reason): void {
		$this->dispatch(
			self::EVENT_END,
			['impersonator' => $impersonatorUid, 'targetUser' => $targetUid, 'reason' => $reason]
		);
	}

	/**
	 * The cleanup at the end of an impersonation can not tell who created a
	 * credential, so it may revoke one the account owner created meanwhile:
	 * the owner is told (notification) and audit apps get an event.
	 *
	 * @param string $name name of the app password or of the session (empty for the URL signing key)
	 * @param string $kind Notifier::CREDENTIAL_*: what it is, so that the notification can say it in
	 *                     the language of the owner
	 */
	public function credentialRevoked(
		string $targetUid,
		string $name,
		?string $impersonatorUid,
		string $kind = Notifier::CREDENTIAL_APP_PASSWORD
	): void {
		// what the event calls the credential (as in version 1.0.1, consumers may rely on it)
		if ($kind === Notifier::CREDENTIAL_SIGNING_KEY) {
			$credential = 'URL signing key';
		} elseif ($kind === Notifier::CREDENTIAL_SESSION) {
			$credential = 'session ' . $name;
		} else {
			$credential = $name;
		}
		$this->dispatch(
			self::EVENT_CREDENTIAL_REVOKED,
			['targetUser' => $targetUid, 'credential' => $credential, 'impersonator' => $impersonatorUid]
		);
		try {
			$notification = $this->notificationManager->createNotification();
			$notification->setApp('impersonate')
				->setUser($targetUid)
				->setDateTime(new \DateTime())
				->setObject('credential', \substr(\sha1($targetUid . "\0" . $credential), 0, 32))
				->setSubject(Notifier::SUBJECT_CREDENTIAL_REVOKED, [$name, $kind]);
			$this->notificationManager->notify($notification);
		} catch (\Throwable $e) {
			$this->logger->logException($e, ['app' => 'impersonate']);
		}
	}

	/**
	 * @param array<string, mixed> $arguments
	 */
	private function dispatch(string $name, array $arguments): void {
		try {
			$this->eventDispatcher->dispatch(new GenericEvent(null, $arguments), $name);
		} catch (\Throwable $e) {
			$this->logger->logException($e, ['app' => 'impersonate']);
		}
	}
}
