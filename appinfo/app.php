<?php
/**
 * Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
 * Maintained by Marek Królikowski (TaKeN): https://github.com/takenek/impersonate
 * Modified on 2026-11-26 and 2026-11-27 by Marek Królikowski (TaKeN): ownCloud 11.1 support and
 * security hardening, see CHANGELOG.md. SPDX-License-Identifier: AGPL-3.0-only
 * See LICENSE and COPYRIGHT.
 *
 * Based on the ownCloud "impersonate" app (https://github.com/owncloud/impersonate):
 *
 * ownCloud - impersonate
 *
 * This file is licensed under the Affero General Public License version 3 or
 * later. See the COPYING file.
 *
 * @author Jörn Friedrich Dreyer <jfd@owncloud.com>
 * @copyright Jörn Friedrich Dreyer 2015
 */

// This is an "authentication" app: its app.php runs on every request, before
// core validates the session. A \Throwable escaping from here would break every
// request of the instance, so everything is guarded.

// Re-validate an active impersonation once all authentication apps are loaded.
// Registered first and without anything that could fail (only the class name is
// needed): the guard has to run even if the rest of this file does not.
try {
	\OC_Hook::connect('OC_App', 'loadedApps', \OCA\Impersonate\ImpersonationGuard::class, 'onLoadedApps');
} catch (\Throwable $e) {
	\OC::$server->getLogger()->logException($e, ['app' => 'impersonate']);
}

try {
	$application = new \OCA\Impersonate\AppInfo\Application();
	$container = $application->getContainer();

	/** @var \OCA\Impersonate\Util $util */
	$util = $container->query(\OCA\Impersonate\Util::class);
	if ($util->isImpersonating()) {
		\OCP\Util::addScript('impersonate', 'impersonate_logout');
		\OCP\Util::addScript('impersonate', 'templates/impersonateNotification.handlebars');
		\OCP\Util::addStyle('impersonate', 'impersonate');
	}

	$eventDispatcher = \OC::$server->getEventDispatcher();
	// --- register js for user management ------------------------------------
	$eventDispatcher->addListener(
		'OC\Settings\Users::loadAdditionalScripts',
		function () {
			\OCP\Util::addScript('impersonate', 'impersonate');
			\OCP\Util::addScript('impersonate', 'templates/addImpersonateIcon.handlebars');
			\OCP\Util::addScript('impersonate', 'templates/removeImpersonateIcon.handlebars');
		}
	);

	// --- switch back to the impersonator on logout ---------------------------
	$eventDispatcher->addListener(
		'\OC\User\Session::pre_logout',
		function (\Symfony\Component\EventDispatcher\GenericEvent $event) use ($container) {
			try {
				/** @var \OCA\Impersonate\LogoutListener $listener */
				$listener = $container->query(\OCA\Impersonate\LogoutListener::class);
				$listener->onPreLogout($event);
			} catch (\Throwable $e) {
				\OC::$server->getLogger()->logException($e, ['app' => 'impersonate']);
			}
		}
	);
} catch (\Throwable $e) {
	\OC::$server->getLogger()->logException($e, ['app' => 'impersonate']);
}

// --- a deleted group does not stay in the delegation list --------------------
try {
	$groupManager = \OC::$server->getGroupManager();
	if ($groupManager instanceof \OC\Group\Manager) {
		$groupManager->listen('\OC\Group', 'postDelete', function ($group) {
			try {
				if ($group instanceof \OCP\IGroup) {
					$application = new \OCA\Impersonate\AppInfo\Application();
					/** @var \OCA\Impersonate\Policy $policy */
					$policy = $application->getContainer()->query(\OCA\Impersonate\Policy::class);
					$policy->forgetGroup($group->getGID());
				}
			} catch (\Throwable $e) {
				\OC::$server->getLogger()->logException($e, ['app' => 'impersonate']);
			}
		});
	}
} catch (\Throwable $e) {
	\OC::$server->getLogger()->logException($e, ['app' => 'impersonate']);
}

// --- the notification an account owner gets about a revoked credential -------
try {
	\OC::$server->getNotificationManager()->registerNotifier(
		function () {
			return new \OCA\Impersonate\Notifier(\OC::$server->getL10NFactory(), \OC::$server->getURLGenerator());
		},
		function () {
			return ['id' => 'impersonate', 'name' => 'Impersonate'];
		}
	);
} catch (\Throwable $e) {
	\OC::$server->getLogger()->logException($e, ['app' => 'impersonate']);
}
