<?php declare(strict_types=1);

/**
 * Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
 * Maintained by Marek Królikowski (TaKeN): https://github.com/takenek/impersonate
 * Modified on 2026-11-26 and 2026-11-27 by Marek Królikowski (TaKeN): ownCloud 11.1 support and
 * security hardening, see CHANGELOG.md. SPDX-License-Identifier: AGPL-3.0-only
 * See LICENSE and COPYRIGHT.
 *
 * Based on the ownCloud "impersonate" app (https://github.com/owncloud/impersonate):
 *
 * ownCloud
 *
 * @author Swikriti Tripathi <swikriti@jankaritech.com>
 * @copyright Copyright (c) 2022 Swikriti Tripathi swikriti@jankaritech.com
 *
 * This code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License,
 * as published by the Free Software Foundation;
 * either version 3 of the License, or any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>
 *
 */

namespace Page;

use Behat\Mink\Element\NodeElement;
use Behat\Mink\Session;
use Exception;

/**
 * Impersonate user page.
 */
class UserImpersonatePage extends UsersPage {
	/**
	 *
	 * @var string $path
	 */
	protected $path = '/index.php/settings/users';
	protected string $impersonateXpath = './/a[@class="action permanent impersonate"]';
	protected string $confirmXpath = '//div[contains(@class, "oc-dialog-buttonrow")]//button[contains(@class, "primary")]';
	protected string $userXpath = '//span[contains(@id,"expandDisplayName") and text()="%s"]';
	protected string $impersonateNotificationXpath = '//div[@id="notification-container"]//div[@id="impersonate-notification"]//a';

	/**
	 * @param Session $session
	 * @param string $user
	 *
	 * @throws Exception
	 */
	public function impersonateUser(Session $session, string $user):void {
		$userFromTable = $this->findUserInTable($user);
		$impersonateButton = $userFromTable->find('xpath', $this->impersonateXpath);
		$this->assertElementNotNull(
			$impersonateButton,
			__METHOD__ . " could not find element with the xpath '$this->impersonateXpath'"
		);
		$impersonateButton->click();
		// the icon asks before it switches: answer the confirmation with "Yes"
		$confirmButton = $this->waitTillXpathIsVisible($this->confirmXpath);
		$this->assertElementNotNull(
			$confirmButton,
			__METHOD__ . " could not find element with the xpath '$this->confirmXpath'"
		);
		$confirmButton->click();
		$this->waitForAjaxCallsToStartAndFinish($session);
	}

	/**
	 * @param string $user
	 *
	 * @return bool
	 *
	 * @throws Exception
	 */
	public function isImpersonateActionAvailable(string $user):bool {
		$userFromTable = $this->findUserInTable($user);
		// the cell is added asynchronously once getimpersonatedata answered:
		// wait for either the action or the empty cell before deciding
		$decided = './/a[@class="action permanent impersonate"] | .//td[contains(@class, "impersonateDisabled")]';
		$end = \microtime(true) + STANDARD_UI_WAIT_TIMEOUT_MILLISEC / 1000;
		while ($userFromTable->find('xpath', $decided) === null && \microtime(true) < $end) {
			\usleep(STANDARD_SLEEP_TIME_MICROSEC);
		}
		$this->assertElementNotNull(
			$userFromTable->find('xpath', $decided),
			__METHOD__ . " the impersonate column of user '$user' was not rendered"
		);
		return $userFromTable->find('xpath', $this->impersonateXpath) !== null;
	}

	/**
	 * @param string $username
	 *
	 * @return bool
	 *
	 * @throws Exception
	 */
	public function userShouldBeInTheirPage(string $username): bool {
		$userFieldElement = $this->waitTillXpathIsVisible(\sprintf($this->userXpath, $username));
		if ($userFieldElement && $userFieldElement->isVisible()) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * @return string
	 *
	 * @throws Exception
	 */
	public function getImpersonationNotificationText(): string {
		$notificationElement = $this->find('xpath', $this->impersonateNotificationXpath);
		$this->assertElementNotNull(
			$notificationElement,
			__METHOD__ . " could not find element with the xpath '$this->impersonateNotificationXpath'"
		);
		return $this->getTrimmedText($notificationElement);
	}
}
