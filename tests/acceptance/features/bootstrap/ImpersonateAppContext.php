<?php declare(strict_types = 1);
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
 * @author Kiran Adhikari <kiran.adhikari@jankaritech>
 *
 * @copyright Copyright (c) 2022, JankariTech
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU AFFERO GENERAL PUBLIC LICENSE
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU AFFERO GENERAL PUBLIC LICENSE for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with this library.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

use Behat\Behat\Context\Context;
use Behat\Behat\Hook\Scope\AfterScenarioScope;
use Behat\Behat\Hook\Scope\BeforeScenarioScope;
use Behat\Gherkin\Node\TableNode;
use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use TestHelpers\SetupHelper;
use TestHelpers\HttpRequestHelper;

require_once 'bootstrap.php';

/**
 * Context for Impersonate app
 */
class ImpersonateAppContext implements Context {
	private FeatureContext $featureContext;
	private bool $subadminFeatureChanged = false;

	/**
	 * Returns base url for the impersonate app
	 *
	 * @return string
	 */
	public function getImpersonateUrl(): string {
		return "/index.php/apps/impersonate/user";
	}

	/**
	 * Get the commands to obtain desired configuration
	 *
	 * @param string $option
	 * @param string|null $value
	 * @return array
	 * @throws Exception
	 */
	public function getOccCommandsForImpersonateOption(string $option, ?string $value = ""): array {
		// what the admin panel stores for each radio button (PUT /apps/impersonate/policy)
		$set = static function (string $key, string $val): string {
			return "config:app:set impersonate $key --value $val";
		};
		switch ($option) {
			case "allow group admins as targets":
				return [
					$set('impersonate_allow_groupadmin_targets', $value === 'true' ? 'true' : 'false'),
				];
			case "allow only an admin":
				return [
					$set('impersonate_all_groupadmins', 'false'),
					$set('impersonate_include_groups', 'false'),
					$set('impersonate_include_groups_list', "'[]'"),
				];
			case "allow all group admins":
				return [
					$set('impersonate_all_groupadmins', 'true'),
					$set('impersonate_include_groups', 'false'),
					$set('impersonate_include_groups_list', "'[]'"),
				];
			case "only group admins of specific groups":
				$groups = \array_values(\array_filter(\array_map('trim', \explode(',', (string)$value)), 'strlen'));
				return [
					$set('impersonate_include_groups', 'true'),
					$set('impersonate_all_groupadmins', 'false'),
					$set('impersonate_include_groups_list', "'" . \json_encode($groups) . "'"),
				];
			default:
				throw new Exception("Invalid option");
		}
	}

	/**
	 * Run an occ command and fail when it does not succeed
	 *
	 * @param string $command
	 * @param array|null $env
	 *
	 * @return void
	 * @throws Exception
	 */
	private function runOccOrFail(string $command, ?array $env = null): void {
		$code = $this->featureContext->runOccWithEnvVariables([$command], $env);
		if ($code !== 0) {
			throw new Exception(
				"occ command '$command' failed with exit code $code: " . $this->featureContext->getStdErrOfOccCommand()
			);
		}
	}

	/**
	 * Create a user with given username, password and group
	 * @param string $username
	 * @param string $password
	 * @param string $group
	 *
	 * @return void
	 * @throws Exception
	 */
	public function createUserWithGroup(string $username, string $password, string $group): void {
		$user = $this->featureContext->getActualUsername($username);
		$actualPassword = $this->featureContext->getActualPassword($password);
		$this->runOccOrFail(
			"user:add $user --password-from-env --group=$group",
			['OC_PASS' => $actualPassword]
		);

		$this->featureContext->addUserToCreatedUsersList(
			$user,
			$password
		);
		$this->featureContext->addGroupToCreatedGroupsList($group);
	}

	/**
	 * @Given /^the administrator has created following users with settings:$/
	 * expects a table of users data
	 * | username | password | groupname | role |
	 * this is using provisioning api
	 *
	 * @param TableNode $table
	 *
	 * @return void
	 * @throws Exception
	 */
	public function createUserWithGroupAndRole(TableNode $table): void {
		$this->featureContext->verifyTableNodeColumns($table, ['username', 'password', 'group'], ['role']);

		foreach ($table as $row) {
			$username = $row['username'];
			$password = $row['password'];
			$group = $row['group'];

			$this->createUserWithGroup($username, $password, $group);

			if ($row['role'] === "group-admin") {
				$this->featureContext->userHasBeenMadeSubadminOfGroup(
					$username,
					$group
				);
			}
		}
	}

	/**
	 * @Given /"([^"]*)" option in impersonate settings has been set to "([^"]*)"$/
	 *
	 * @param string $option
	 * @param string|null $value
	 * @throws Exception
	 */
	public function setImpersonateSettings(string $option, ?string $value = ""): void {
		foreach ($this->getOccCommandsForImpersonateOption($option, $value) as $occCommand) {
			$this->runOccOrFail($occCommand);
		}
	}

	/**
	 * ownCloud 11 disables the group admin (subadmin) feature unless the
	 * system config "allow_subadmins" is true.
	 *
	 * @Given /^the group admin feature has been (enabled|disabled)$/
	 *
	 * @param string $state
	 *
	 * @return void
	 * @throws Exception
	 */
	public function theGroupAdminFeatureHasBeen(string $state): void {
		$value = $state === 'enabled' ? 'true' : 'false';
		$this->runOccOrFail("config:system:set allow_subadmins --value $value --type boolean");
		$this->subadminFeatureChanged = true;
	}

	/**
	 * The CSRF token of the session as the pages of ownCloud carry it
	 *
	 * @param string $html
	 *
	 * @return string
	 * @throws Exception
	 */
	private static function requestToken(string $html): string {
		if (\preg_match('/data-requesttoken="([^"]*)"/', $html, $matches) !== 1) {
			throw new Exception("the page has no request token");
		}
		return \html_entity_decode($matches[1], ENT_QUOTES);
	}

	/**
	 * An impersonation can only be started from an interactive session (not by
	 * a request that is authenticated with HTTP Basic credentials): log in
	 * through the login form like a browser and send the CSRF token.
	 *
	 * @When /^"([^"]*)" sends a request to impersonate user "([^"]*)"$/
	 *
	 * @param string $requester
	 * @param string $impersonateUser
	 * @return void
	 * @throws Exception|\GuzzleHttp\Exception\GuzzleException
	 */
	public function sendRequestToImpersonateUser(string $requester, string $impersonateUser): void {
		$requestData = [
				"target" => $this->featureContext->getActualUsername($impersonateUser)
			];

		if ($requester === "admin") {
			$userName =  $this->featureContext->getAdminUsername();
			$password = $this->featureContext->getAdminPassword();
		} else {
			$userName = $this->featureContext->getActualUsername($requester);
			$password = $this->featureContext->getActualPassword($requester);
		}
		$baseUrl = $this->featureContext->getBaseUrl();
		// one browser-like client per request: its own session cookies, HTTP error codes are answers
		$client = new Client(['cookies' => new CookieJar(), 'http_errors' => false]);
		$loginPage = $client->get($baseUrl . '/index.php/login');
		$client->post(
			$baseUrl . '/index.php/login',
			[
				'form_params' => [
					'user' => $userName,
					'password' => $password,
					'requesttoken' => self::requestToken((string)$loginPage->getBody()),
					'timezone' => 'UTC',
					'timezone-offset' => '0',
				],
			]
		);
		$page = $client->get($baseUrl . '/index.php/apps/files/');
		$response = $client->post(
			$baseUrl . $this->getImpersonateUrl(),
			[
				'headers' => ['requesttoken' => self::requestToken((string)$page->getBody())],
				'form_params' => $requestData,
			]
		);
		$this->featureContext->setResponse($response);
	}

	/**
	 * @When /^"([^"]*)" sends a request with HTTP Basic credentials to impersonate user "([^"]*)"$/
	 *
	 * @param string $requester
	 * @param string $impersonateUser
	 * @return void
	 * @throws JsonException|\GuzzleHttp\Exception\GuzzleException
	 */
	public function sendBasicAuthRequestToImpersonateUser(string $requester, string $impersonateUser): void {
		if ($requester === "admin") {
			$userName =  $this->featureContext->getAdminUsername();
			$password = $this->featureContext->getAdminPassword();
		} else {
			$userName = $this->featureContext->getActualUsername($requester);
			$password = $this->featureContext->getActualPassword($requester);
		}
		// HttpRequestHelper returns the response for HTTP error codes as well
		$response = HttpRequestHelper::post(
			$this->featureContext->getBaseUrl() . $this->getImpersonateUrl(),
			'',
			$userName,
			$password,
			null,
			["target" => $this->featureContext->getActualUsername($impersonateUser)]
		);
		$this->featureContext->setResponse($response);
	}

	/**
	 * @AfterScenario
	 *
	 * @param AfterScenarioScope $scope
	 *
	 * @return void
	 * @throws Exception
	 */
	public function resetSubadminFeature(AfterScenarioScope $scope): void {
		if ($this->subadminFeatureChanged) {
			$this->featureContext->runOccWithEnvVariables(['config:system:delete allow_subadmins']);
			$this->subadminFeatureChanged = false;
		}
		// the scenarios do not log out: end the impersonations they started
		$this->featureContext->runOccWithEnvVariables(['impersonate:active --end']);
	}

	/**
	 * @BeforeScenario
	 *
	 * @param BeforeScenarioScope $scope
	 *
	 * @return void
	 * @throws Exception
	 */
	public function setUpScenario(BeforeScenarioScope $scope): void {
		// Get the environment
		$environment = $scope->getEnvironment();
		// Get all the contexts you need in this context
		$this->featureContext = $environment->getContext('FeatureContext');
		SetupHelper::init(
			$this->featureContext->getAdminUsername(),
			$this->featureContext->getAdminPassword(),
			$this->featureContext->getBaseUrl(),
			$this->featureContext->getOcPath()
		);
	}
}
