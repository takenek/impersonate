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
 * @author Sujith Haridasan <sharidasan@owncloud.com>
 *
 * @copyright Copyright (c) 2017, ownCloud GmbH
 * @license AGPL-3.0
 *
 * This code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License, version 3,
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

namespace OCA\Impersonate;

use OCP\IConfig;
use OCP\Settings\ISettings;
use OCP\Template;

class AdminPanel implements ISettings {
	/** @var IConfig */
	private $config;
	/** @var Policy */
	private $policy;

	public function __construct(IConfig $config, Policy $policy) {
		$this->config = $config;
		$this->policy = $policy;
	}

	public function getPanel() {
		$t = new Template('impersonate', 'settings-admin');
		$t->assign('appEnabled', $this->config->getAppValue('impersonate', 'enabled', 'no') !== 'no');
		$t->assign('allGroupAdmins', $this->policy->isAllGroupAdminsMode());
		$t->assign('includeGroups', $this->policy->isIncludeGroupsMode());
		$t->assign('includedGroups', $this->policy->getIncludedGroups());
		$t->assign('groupAdminFeatureEnabled', $this->policy->isGroupAdminFeatureEnabled());
		return $t;
	}

	public function getSectionID() {
		return 'authentication';
	}

	public function getPriority() {
		return 0;
	}
}
