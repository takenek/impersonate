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

use OCP\IURLGenerator;
use OCP\L10N\IFactory;
use OCP\Notification\INotification;
use OCP\Notification\INotifier;

/**
 * Renders the notification an account owner gets when the cleanup at the end
 * of an impersonation revoked one of their credentials (see AuditTrail).
 */
class Notifier implements INotifier {
	public const SUBJECT_CREDENTIAL_REVOKED = 'credential_revoked';

	/** @var IFactory */
	private $l10nFactory;
	/** @var IURLGenerator */
	private $urlGenerator;

	public function __construct(IFactory $l10nFactory, IURLGenerator $urlGenerator) {
		$this->l10nFactory = $l10nFactory;
		$this->urlGenerator = $urlGenerator;
	}

	/**
	 * @param string $languageCode
	 * @throws \InvalidArgumentException when the notification is not one of this app
	 */
	public function prepare(INotification $notification, $languageCode) {
		if ($notification->getApp() !== 'impersonate'
			|| $notification->getSubject() !== self::SUBJECT_CREDENTIAL_REVOKED
		) {
			throw new \InvalidArgumentException('Unknown notification');
		}
		$parameters = $notification->getSubjectParameters();
		$credential = isset($parameters[0]) ? (string)$parameters[0] : '';
		$l = $this->l10nFactory->get('impersonate', $languageCode);
		$notification->setParsedSubject(
			(string)$l->t(
				'"%s" was revoked for security reasons at the end of an impersonation of your account. If you created it yourself, please create it again.',
				[$credential]
			)
		);
		// where the user finds the sessions and app passwords of the account
		$notification->setLink(
			$this->urlGenerator->getAbsoluteURL('/index.php/settings/personal?sectionid=security')
		);
		return $notification;
	}
}
