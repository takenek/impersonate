<?php
/**
 * Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
 * Maintained by Marek Królikowski (TaKeN): https://github.com/takenek/impersonate
 * Modified on 2026-11-26 by Marek Królikowski (TaKeN): ownCloud 11.1 support and security
 * hardening, see CHANGELOG.md. SPDX-License-Identifier: AGPL-3.0-only
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

$application = new \OCA\Impersonate\AppInfo\Application();
$application->registerRoutes(
	// @phan-suppress-next-line PhanUndeclaredThis
	$this,
	[
		'routes' => [

			// Land in users setting page ( for admin user only )
			[
				'name' => 'Settings#impersonate',
				'url' => '/user',
				'verb' => 'POST',
			],

			// NOTE: switching back to the impersonator is handled by the
			// '\OC\User\Session::pre_logout' listener registered in appinfo/app.php,
			// not by an HTTP route. The former 'admin_settings#impersonateAdminTemplate'
			// and 'Logout#logoutcontroller' routes pointed to controllers that cannot be
			// dispatched and only produced HTTP 500 errors, so they were removed.

			//Get the data to validate for the app
			[
				'name' => 'Settings#getDataForImpersonateApp',
				'url' => '/getimpersonatedata',
				'verb' => 'GET',
			]

		],
	]
);
