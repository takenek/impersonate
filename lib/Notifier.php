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

	/** what was revoked: the second subject parameter (the first one is its name) */
	public const CREDENTIAL_APP_PASSWORD = 'app_password';
	public const CREDENTIAL_SESSION = 'session';
	public const CREDENTIAL_SIGNING_KEY = 'signing_key';

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
		// as CredentialCleanup writes it since 1.0.4 (a notification stored by an earlier version may
		// hold the name as its client gave it)
		$name = isset($parameters[0]) ? CredentialCleanup::printable((string)$parameters[0]) : '';
		// A notification that version 1.0.1 stored has no kind: its first parameter is the whole
		// label ("session <name>", "URL signing key") and gets the general text.
		$kind = isset($parameters[1]) ? (string)$parameters[1] : self::CREDENTIAL_APP_PASSWORD;
		$l = $this->l10nFactory->get('impersonate', $languageCode);
		// every text is a whole sentence of its own, so that nothing untranslated is put into a translation
		if ($kind === self::CREDENTIAL_SIGNING_KEY) {
			$subject = $l->t(
				'The URL signing key of your account was removed for security reasons at the end of an impersonation of your account. A new key is created when one is needed.'
			);
		} elseif ($kind === self::CREDENTIAL_SESSION) {
			$subject = $l->t(
				'The session "%s" of your account was ended for security reasons at the end of an impersonation of your account. If it was your own session, please log in again.',
				[$name]
			);
		} else {
			$subject = $l->t(
				'"%s" was revoked for security reasons at the end of an impersonation of your account. If you created it yourself, please create it again.',
				[$name]
			);
		}
		$notification->setParsedSubject((string)$subject);
		// where the user finds the sessions and app passwords of the account
		$notification->setLink(
			$this->urlGenerator->getAbsoluteURL('/index.php/settings/personal?sectionid=security')
		);
		return $notification;
	}
}
