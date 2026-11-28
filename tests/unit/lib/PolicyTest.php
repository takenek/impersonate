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

namespace OCA\Impersonate\Tests\Unit\Lib;

use OC\SubAdmin;
use OCA\Impersonate\Policy;
use OCP\DB\QueryBuilder\IExpressionBuilder;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IConfig;
use OCP\IDBConnection;
use OCP\IGroup;
use OCP\IGroupManager;
use OCP\ILogger;
use OCP\IUser;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

class PolicyTest extends TestCase {
	/** @var IConfig|MockObject */
	private $config;
	/** @var IGroupManager|MockObject */
	private $groupManager;
	/** @var SubAdmin|MockObject */
	private $subAdmin;
	/** @var array */
	private $appConfig = [];
	/** @var string[] */
	private $admins = ['admin'];
	/** @var array<string, string[]> uid => groups */
	private $memberships = [];
	/** @var array<string, string[]> uid => groups the user administers */
	private $subAdminOf = [];
	/** @var bool */
	private $groupAdminFeature = true;
	/** @var string[] */
	private $existingGroups = ['g1', 'g2', 'g3'];
	/** @var array[] [key, value] of the setAppValue() calls */
	private $written = [];
	/** @var int|null number of the setAppValue() call that fails */
	private $failOnWrite;

	protected function setUp(): void {
		parent::setUp();
		$this->config = $this->createMock(IConfig::class);
		$this->config->method('getAppValue')->willReturnCallback(
			function ($app, $key, $default = '') {
				return $this->appConfig[$key] ?? $default;
			}
		);
		$this->groupManager = $this->createMock(IGroupManager::class);
		$this->groupManager->method('isAdmin')->willReturnCallback(
			function ($uid) {
				return \in_array($uid, $this->admins, true);
			}
		);
		$this->groupManager->method('isInGroup')->willReturnCallback(
			function ($uid, $gid) {
				return \in_array($gid, $this->memberships[$uid] ?? [], true);
			}
		);
		$this->subAdmin = $this->createMock(SubAdmin::class);
		$this->subAdmin->method('isEnabled')->willReturnCallback(function () {
			return $this->groupAdminFeature;
		});
		$this->subAdmin->method('isSubAdmin')->willReturnCallback(function (IUser $user) {
			return $this->groupAdminFeature && !empty($this->subAdminOf[$user->getUID()]);
		});
		$this->subAdmin->method('getAllSubAdmins')->willReturnCallback(function () {
			$all = [];
			foreach ($this->subAdminOf as $uid => $gids) {
				foreach ($gids as $gid) {
					$group = $this->createMock(IGroup::class);
					$group->method('getGID')->willReturn($gid);
					$all[] = ['user' => $this->user((string)$uid), 'group' => $group];
				}
			}
			return $all;
		});
		$this->groupManager->method('groupExists')->willReturnCallback(function ($gid) {
			return \in_array($gid, $this->existingGroups, true);
		});
		$this->config->method('setAppValue')->willReturnCallback(function ($app, $key, $value) {
			$this->written[] = [$key, $value];
			if ($this->failOnWrite !== null && \count($this->written) === $this->failOnWrite) {
				throw new \RuntimeException('database down');
			}
			$this->appConfig[$key] = $value;
		});
		$this->subAdmin->method('getSubAdminsGroups')->willReturnCallback(function (IUser $user) {
			if (!$this->groupAdminFeature) {
				return [];
			}
			return \array_map(function ($gid) {
				$group = $this->createMock(IGroup::class);
				$group->method('getGID')->willReturn($gid);
				return $group;
			}, $this->subAdminOf[$user->getUID()] ?? []);
		});
	}

	private function policy(): Policy {
		return new Policy($this->config, $this->groupManager, $this->subAdmin);
	}

	/**
	 * @return IUser|MockObject
	 */
	private function user(string $uid, bool $enabled = true) {
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn($uid);
		$user->method('isEnabled')->willReturn($enabled);
		return $user;
	}

	public static function groupListProvider(): array {
		return [
			['["g1","g2"]', ['g1', 'g2']],
			['["g1","g1",""]', ['g1']],
			['[]', []],
			['', []],
			['null', []],
			['"g1"', []],
			['true', []],
			['{"a":"g1"}', []],
			// an object is no list, whatever its keys are
			['{"0":"g1","1":"g2"}', []],
			['[["g1"],1,null,"g2"]', ['g2']],
			['garbage', []],
			[null, []],
		];
	}

	/**
	 * @dataProvider groupListProvider
	 *
	 * @param mixed $raw
	 * @param string[] $expected
	 */
	public function testDecodeGroupList($raw, array $expected): void {
		$this->assertSame($expected, Policy::decodeGroupList($raw));
	}

	public function testNobodyCanImpersonateThemselves(): void {
		$this->assertSame(Policy::ERROR_CANNOT_IMPERSONATE, $this->policy()->check($this->user('admin'), $this->user('Admin')));
	}

	public function testDisabledImpersonatorIsRefused(): void {
		$this->assertSame(Policy::ERROR_CANNOT_IMPERSONATE, $this->policy()->check($this->user('admin', false), $this->user('alice')));
	}

	public function testAdminMayImpersonateAnyEnabledUser(): void {
		$this->admins[] = 'admin2';
		$policy = $this->policy();
		$this->assertNull($policy->check($this->user('admin'), $this->user('alice')));
		$this->assertNull($policy->check($this->user('admin'), $this->user('admin2')));
		$this->assertSame(Policy::ERROR_DISABLED_TARGET, $policy->check($this->user('admin'), $this->user('alice', false)));
		$this->assertTrue($policy->mayImpersonateAnyone($this->user('admin')));
	}

	public function testNormalUserMayNotImpersonate(): void {
		$this->appConfig['impersonate_all_groupadmins'] = 'true';
		$this->memberships = ['bob' => ['g1'], 'alice' => ['g1']];
		$policy = $this->policy();
		$this->assertFalse($policy->mayImpersonateAnyone($this->user('bob')));
		$this->assertSame(Policy::ERROR_CANNOT_IMPERSONATE, $policy->check($this->user('bob'), $this->user('alice')));
	}

	public function testAllGroupAdminsMode(): void {
		$this->appConfig['impersonate_all_groupadmins'] = 'true';
		$this->subAdminOf = ['carol' => ['g1']];
		$this->memberships = ['alice' => ['g1'], 'bob' => ['g2'], 'admin' => ['g1']];
		$policy = $this->policy();
		$this->assertTrue($policy->mayImpersonateAnyone($this->user('carol')));
		$this->assertSame(['g1'], $policy->getImpersonableGroupIds($this->user('carol')));
		$this->assertNull($policy->check($this->user('carol'), $this->user('alice')));
		$this->assertSame(Policy::ERROR_CANNOT_IMPERSONATE, $policy->check($this->user('carol'), $this->user('bob')));
		$this->assertSame(Policy::ERROR_ADMIN_TARGET, $policy->check($this->user('carol'), $this->user('admin')));
		$this->assertSame(Policy::ERROR_DISABLED_TARGET, $policy->check($this->user('carol'), $this->user('alice', false)));
	}

	public function testIncludeGroupsMode(): void {
		$this->appConfig['impersonate_include_groups'] = 'true';
		$this->appConfig['impersonate_include_groups_list'] = '["g1","g3"]';
		$this->subAdminOf = ['carol' => ['g1', 'g2']];
		$this->memberships = ['alice' => ['g1'], 'bob' => ['g2']];
		$policy = $this->policy();
		$this->assertTrue($policy->isIncludeGroupsMode());
		$this->assertSame(['g1'], $policy->getImpersonableGroupIds($this->user('carol')));
		$this->assertNull($policy->check($this->user('carol'), $this->user('alice')));
		// carol administers g2, but g2 is not one of the included groups
		$this->assertSame(Policy::ERROR_CANNOT_IMPERSONATE, $policy->check($this->user('carol'), $this->user('bob')));
	}

	public function testLeftoverGroupListIsIgnoredWhenOnlyAdminsAreAllowed(): void {
		$this->appConfig['impersonate_include_groups'] = 'false';
		$this->appConfig['impersonate_include_groups_list'] = '["g1"]';
		$this->subAdminOf = ['carol' => ['g1']];
		$this->memberships = ['alice' => ['g1']];
		$policy = $this->policy();
		$this->assertFalse($policy->mayImpersonateAnyone($this->user('carol')));
		$this->assertSame(Policy::ERROR_CANNOT_IMPERSONATE, $policy->check($this->user('carol'), $this->user('alice')));
	}

	public function testGroupAdminFeatureDisabled(): void {
		$this->groupAdminFeature = false;
		$this->appConfig['impersonate_all_groupadmins'] = 'true';
		$this->subAdminOf = ['carol' => ['g1']];
		$this->memberships = ['alice' => ['g1']];
		$policy = $this->policy();
		$this->assertFalse($policy->isGroupAdminFeatureEnabled());
		$this->assertFalse($policy->mayImpersonateAnyone($this->user('carol')));
		$this->assertSame([], $policy->getImpersonableGroupIds($this->user('carol')));
		$this->assertSame(Policy::ERROR_CANNOT_IMPERSONATE, $policy->check($this->user('carol'), $this->user('alice')));
		// admins are not affected
		$this->assertNull($policy->check($this->user('admin'), $this->user('alice')));
	}

	public function testPolicyChecksTheGroupAdminFeatureItself(): void {
		// even if SubAdmin itself would still report group admin rights
		$subAdmin = $this->createMock(SubAdmin::class);
		$subAdmin->method('isEnabled')->willReturn(false);
		$subAdmin->method('isSubAdmin')->willReturn(true);
		$group = $this->createMock(IGroup::class);
		$group->method('getGID')->willReturn('g1');
		$subAdmin->method('getSubAdminsGroups')->willReturn([$group]);
		$this->appConfig['impersonate_all_groupadmins'] = 'true';
		$this->memberships = ['alice' => ['g1']];
		$policy = new Policy($this->config, $this->groupManager, $subAdmin);
		$this->assertFalse($policy->mayImpersonateAnyone($this->user('carol')));
		$this->assertSame(Policy::ERROR_CANNOT_IMPERSONATE, $policy->check($this->user('carol'), $this->user('alice')));
	}

	public function testAdminUidsInGroups(): void {
		$this->memberships = ['admin' => ['g1'], 'admin2' => ['g2'], 'alice' => ['g1']];
		$adminGroup = $this->createMock(IGroup::class);
		$adminGroup->method('getUsers')->willReturn([$this->user('admin'), $this->user('admin2')]);
		$this->groupManager->method('get')->with('admin')->willReturn($adminGroup);
		$policy = $this->policy();
		$this->assertSame(['admin'], $policy->getAdminUidsInGroups(['g1']));
		$this->assertSame([], $policy->getAdminUidsInGroups([]));
	}

	public function testAllGroupAdminsModeWinsOverIncludeGroups(): void {
		$this->appConfig['impersonate_all_groupadmins'] = 'true';
		$this->appConfig['impersonate_include_groups'] = 'true';
		$policy = $this->policy();
		$this->assertTrue($policy->isAllGroupAdminsMode());
		$this->assertFalse($policy->isIncludeGroupsMode());
	}

	public function testGroupAdminsCanNotImpersonateGroupAdminsByDefault(): void {
		$this->appConfig['impersonate_all_groupadmins'] = 'true';
		// erin is a member of carol's group and administers another group
		$this->subAdminOf = ['carol' => ['g1'], 'erin' => ['g2']];
		$this->memberships = ['alice' => ['g1'], 'erin' => ['g1']];
		$policy = $this->policy();
		$this->assertNull($policy->check($this->user('carol'), $this->user('alice')));
		$this->assertSame(Policy::ERROR_ADMIN_TARGET, $policy->check($this->user('carol'), $this->user('erin')));
		$this->assertSame(['erin'], $policy->getGroupAdminUidsInGroups(['g1']));
		$this->assertSame([], $policy->getGroupAdminUidsInGroups([]));
		// administrators are not restricted
		$this->assertNull($policy->check($this->user('admin'), $this->user('erin')));
	}

	public function testGroupAdminsCanImpersonateGroupAdminsWhenThatIsAllowed(): void {
		$this->appConfig['impersonate_all_groupadmins'] = 'true';
		$this->appConfig['impersonate_allow_groupadmin_targets'] = 'true';
		$this->subAdminOf = ['carol' => ['g1'], 'erin' => ['g2']];
		$this->memberships = ['erin' => ['g1']];
		$policy = $this->policy();
		$this->assertTrue($policy->allowsGroupAdminTargets());
		$this->assertNull($policy->check($this->user('carol'), $this->user('erin')));
		$this->assertSame([], $policy->getGroupAdminUidsInGroups(['g1']));
	}

	public static function maxDurationProvider(): array {
		return [
			'default' => [null, 3600],
			'configured' => ['15', 900],
			'no limit' => ['0', 0],
			// a broken value never removes the limit
			'empty' => ['', 3600],
			'negative' => ['-5', 3600],
			'not a number' => ['unlimited', 3600],
			'fraction' => ['1.5', 3600],
			'too long' => ['99999999', 3600],
			// only exactly "0" removes the limit; white space around a number does not matter otherwise
			'no limit, with a line break' => ["0\n", 3600],
			'no limit, written as 00' => ['00', 3600],
			'configured, with a line break' => ["15\n", 900],
			'configured, with spaces' => [' 15 ', 900],
		];
	}

	/**
	 * @dataProvider maxDurationProvider
	 */
	public function testMaxDuration(?string $configured, int $seconds): void {
		if ($configured !== null) {
			$this->appConfig['max_duration_minutes'] = $configured;
		}
		$this->assertSame($seconds, $this->policy()->getMaxDuration());
	}

	public function testHasExceededMaxDuration(): void {
		$policy = $this->policy();
		$this->assertFalse($policy->hasExceededMaxDuration(1000, 1000 + 3600));
		$this->assertTrue($policy->hasExceededMaxDuration(1000, 1000 + 3601));
		$this->assertFalse($policy->hasExceededMaxDuration(\time()));
		// an impersonation without a known start can not be bounded
		$this->assertTrue($policy->hasExceededMaxDuration(null));
		$this->appConfig['max_duration_minutes'] = '0';
		$this->assertFalse($policy->hasExceededMaxDuration(1000, 1000 + 10 ** 8));
		$this->assertFalse($policy->hasExceededMaxDuration(null));
	}

	public static function forbiddenPrefixesProvider(): array {
		return [
			['["/apps/tokens/","/apps/Other_App/api/v1/"]', ['/apps/tokens/', '/apps/other_app/api/v1/'], []],
			['["/apps/tokens/","/apps/tokens/","/apps/Tokens"]', ['/apps/tokens/'], []],
			// a missing trailing slash is added: such an entry must not be dropped silently
			['["/apps/tokens"]', ['/apps/tokens/'], []],
			// the guard compares paths without their entry point: so are the prefixes
			['["/index.php/apps/tokens/","/ocs/v1.php/cloud/users","/OCS/v2.php/Cloud/Users/"]', ['/apps/tokens/', '/cloud/users/'], []],
			// an entry point alone is no prefix
			['["/index.php/","/ocs/v1.php"]', [], ['/index.php/', '/ocs/v1.php']],
			// only plain paths: nothing that could match everything, and what is ignored is named
			[
				'["/","//","apps/tokens/","/apps//x/","/apps/to kens/","/apps/t%6fkens/","","/apps/tokens/\n",5,["/apps/x/"],"/apps/ok/"]',
				['/apps/ok/'],
				['/', '//', 'apps/tokens/', '/apps//x/', '/apps/to kens/', '/apps/t%6fkens/', '', "/apps/tokens/\n", '5', '["\/apps\/x\/"]'],
			],
			// not a list at all: nothing is used, the whole value is reported
			['"/apps/tokens/"', [], ['"/apps/tokens/"']],
			['{"a":"/apps/tokens/"}', [], ['{"a":"/apps/tokens/"}']],
			// what 1.0.3 refused, 1.0.4 refuses as well: an object with the keys 0, 1, ... is a list here
			['{"0":"/apps/tokens/","1":"/apps/other/"}', ['/apps/tokens/', '/apps/other/'], []],
			['{"1":"/apps/tokens/"}', [], ['{"1":"/apps/tokens/"}']],
			['garbage', [], ['garbage']],
			['', [], []],
			['[]', [], []],
		];
	}

	/**
	 * @dataProvider forbiddenPrefixesProvider
	 */
	public function testExtraForbiddenPrefixes(string $configured, array $expected, array $ignored): void {
		$this->appConfig['forbidden_prefixes'] = $configured;
		$this->assertSame($expected, $this->policy()->getExtraForbiddenPrefixes());
		$this->assertSame($ignored, $this->policy()->getIgnoredForbiddenPrefixes());
	}

	public function testStartWithCredentialsIsOffUnlessTheOperatorTurnsItOn(): void {
		$this->assertFalse($this->policy()->allowsStartWithCredentials());
		foreach (['yes', '1', 'TRUE', ''] as $value) {
			$this->appConfig['allow_start_with_credentials'] = $value;
			$this->assertFalse($this->policy()->allowsStartWithCredentials(), $value);
		}
		$this->appConfig['allow_start_with_credentials'] = 'true';
		$this->assertTrue($this->policy()->allowsStartWithCredentials());
	}

	public function testDescribe(): void {
		$policy = $this->policy();
		$this->assertSame(['mode' => Policy::MODE_ADMINS, 'groups' => [], 'allowGroupAdminTargets' => false], $policy->describe());
		$this->appConfig['impersonate_include_groups'] = 'true';
		$this->appConfig['impersonate_include_groups_list'] = '["g1"]';
		$this->appConfig['impersonate_allow_groupadmin_targets'] = 'true';
		$this->assertSame(['mode' => Policy::MODE_INCLUDE_GROUPS, 'groups' => ['g1'], 'allowGroupAdminTargets' => true], $policy->describe());
		$this->appConfig['impersonate_all_groupadmins'] = 'true';
		// the list is not in effect
		$this->assertSame(['mode' => Policy::MODE_ALL_GROUP_ADMINS, 'groups' => [], 'allowGroupAdminTargets' => true], $policy->describe());
	}

	public function testStoreKeepsOnlyExistingGroups(): void {
		$stored = $this->policy()->store(Policy::MODE_INCLUDE_GROUPS, ['g1', 'gone', 'g1', '', 5, ['g2'], 'g3'], true);
		$this->assertSame(['mode' => Policy::MODE_INCLUDE_GROUPS, 'groups' => ['g1', 'g3'], 'allowGroupAdminTargets' => true], $stored);
		$this->assertSame('["g1","g3"]', $this->appConfig['impersonate_include_groups_list']);
		$this->assertSame('true', $this->appConfig['impersonate_include_groups']);
		$this->assertSame('false', $this->appConfig['impersonate_all_groupadmins']);
		// the consent is stored with the delegation it was given for
		$this->assertSame('{"mode":"include_groups","groups":["g1","g3"]}', $this->appConfig['impersonate_allow_groupadmin_targets']);
	}

	public function testStoreForgetsTheGroupListInTheOtherModes(): void {
		$this->appConfig['impersonate_include_groups'] = 'true';
		$this->appConfig['impersonate_include_groups_list'] = '["g1"]';
		$stored = $this->policy()->store(Policy::MODE_ALL_GROUP_ADMINS, ['g1'], false);
		$this->assertSame(['mode' => Policy::MODE_ALL_GROUP_ADMINS, 'groups' => [], 'allowGroupAdminTargets' => false], $stored);
		$this->assertSame('[]', $this->appConfig['impersonate_include_groups_list']);
		$this->assertSame('false', $this->appConfig['impersonate_include_groups']);
	}

	public function testStoreRefusesAnUnknownModeWithoutWritingAnything(): void {
		try {
			$this->policy()->store('everybody', [], true);
			$this->fail('exception expected');
		} catch (\InvalidArgumentException $e) {
		}
		$this->assertSame([], $this->written);
	}

	public static function transitionProvider(): array {
		$admins = ['mode' => Policy::MODE_ADMINS, 'groups' => [], 'allowGroupAdminTargets' => false];
		$all = ['mode' => Policy::MODE_ALL_GROUP_ADMINS, 'groups' => [], 'allowGroupAdminTargets' => true];
		$g1 = ['mode' => Policy::MODE_INCLUDE_GROUPS, 'groups' => ['g1'], 'allowGroupAdminTargets' => false];
		$g2 = ['mode' => Policy::MODE_INCLUDE_GROUPS, 'groups' => ['g2'], 'allowGroupAdminTargets' => true];
		$cases = [];
		foreach (['admins' => $admins, 'all' => $all, 'g1' => $g1, 'g2' => $g2] as $fromName => $from) {
			foreach (['admins' => $admins, 'all' => $all, 'g1' => $g1, 'g2' => $g2] as $toName => $to) {
				for ($failing = 1; $failing <= 5; $failing++) {
					$cases["$fromName -> $toName, write $failing fails"] = [$from, $to, $failing];
				}
			}
		}
		return $cases;
	}

	/**
	 * @dataProvider transitionProvider
	 */
	public function testAStoreThatFailsHalfWayNeverLeavesABroaderPolicy(array $from, array $to, int $failing): void {
		$policy = $this->policy();
		$policy->store($from['mode'], $from['groups'], $from['allowGroupAdminTargets']);
		$this->assertSame($from, $policy->describe());
		$this->written = [];
		$this->failOnWrite = $failing;
		try {
			$policy->store($to['mode'], $to['groups'], $to['allowGroupAdminTargets']);
		} catch (\RuntimeException $e) {
		}
		$left = $policy->describe();
		// May a group admin of $gid impersonate a member of it (who is a group admin or not)?
		$permits = static function (array $policy, string $gid, bool $targetIsGroupAdmin): bool {
			$group = $policy['mode'] === Policy::MODE_ALL_GROUP_ADMINS
				|| ($policy['mode'] === Policy::MODE_INCLUDE_GROUPS && \in_array($gid, $policy['groups'], true));
			return $group && (!$targetIsGroupAdmin || $policy['allowGroupAdminTargets']);
		};
		// whatever is left allows nothing that neither the old nor the new policy allows
		foreach ($this->existingGroups as $gid) {
			foreach ([false, true] as $targetIsGroupAdmin) {
				$this->assertTrue(
					!$permits($left, $gid, $targetIsGroupAdmin)
						|| $permits($from, $gid, $targetIsGroupAdmin)
						|| $permits($to, $gid, $targetIsGroupAdmin),
					"$gid, group admin as target: " . \var_export($targetIsGroupAdmin, true) . ', left: ' . \json_encode($left)
				);
			}
		}
	}

	public function testForgetGroup(): void {
		$this->appConfig['impersonate_include_groups_list'] = '["g1","g2"]';
		$policy = $this->policy();
		$policy->forgetGroup('g1');
		$this->assertSame('["g2"]', $this->appConfig['impersonate_include_groups_list']);
		$this->written = [];
		$policy->forgetGroup('unrelated');
		$this->assertSame([], $this->written, 'nothing is written for a group that is not listed');
	}

	public function testTheConsentToGroupAdminsAsTargetsIsBoundToTheDelegation(): void {
		$policy = $this->policy();
		$policy->store(Policy::MODE_INCLUDE_GROUPS, ['g1'], true);
		$this->assertTrue($policy->allowsGroupAdminTargets());
		// another delegation than the one the consent was given for: it does not apply
		$this->appConfig['impersonate_include_groups_list'] = '["g1","g2"]';
		$this->assertFalse($policy->allowsGroupAdminTargets());
		$this->appConfig['impersonate_include_groups_list'] = '["g1"]';
		$this->assertTrue($policy->allowsGroupAdminTargets());
		$this->appConfig['impersonate_all_groupadmins'] = 'true';
		$this->assertFalse($policy->allowsGroupAdminTargets());
		$this->assertSame(['mode' => Policy::MODE_ALL_GROUP_ADMINS, 'groups' => [], 'allowGroupAdminTargets' => false], $policy->describe());
		// "true" (occ, a version before 1.0.4) is a consent without that binding
		$this->appConfig['impersonate_allow_groupadmin_targets'] = 'true';
		$this->assertTrue($policy->allowsGroupAdminTargets());
		foreach (['', 'yes', '{"mode":"all_groupadmins"}', '{"mode":"all_groupadmins","groups":{"a":"g1"}}', '[]', 'null'] as $broken) {
			$this->appConfig['impersonate_allow_groupadmin_targets'] = $broken;
			$this->assertFalse($policy->allowsGroupAdminTargets(), $broken);
		}
	}

	public function testAConsentGivenForAdministratorsOnlyDoesNotApplyInAnotherMode(): void {
		// the admin page sends the option with every save; in "administrators only" it has no effect
		$policy = $this->policy();
		$this->assertSame(
			['mode' => Policy::MODE_ADMINS, 'groups' => [], 'allowGroupAdminTargets' => true],
			$policy->store(Policy::MODE_ADMINS, [], true)
		);
		$this->assertSame('{"mode":"admins","groups":[]}', $this->appConfig['impersonate_allow_groupadmin_targets']);
		// another mode (e.g. set with occ): the consent was not given for it
		$this->appConfig['impersonate_all_groupadmins'] = 'true';
		$this->assertFalse($policy->allowsGroupAdminTargets());
		$this->subAdminOf = ['carol' => ['g1']];
		$this->memberships = ['carol' => ['g1'], 'erin' => ['g1']];
		$this->subAdminOf['erin'] = ['g2'];
		$this->assertSame(Policy::ERROR_ADMIN_TARGET, $policy->check($this->user('carol'), $this->user('erin')));
	}

	public function testAGroupDeletedWhileTheSaveIsStoredDoesNotStayInTheList(): void {
		// g3 exists when the request is validated and is deleted before the list is written: the
		// deletion's cleanup (forgetGroup()) ran before, so the save itself has to drop it
		$asked = 0;
		$groupManager = $this->createMock(IGroupManager::class);
		$groupManager->method('groupExists')->willReturnCallback(function ($gid) use (&$asked) {
			return $gid === 'g1' || ($gid === 'g3' && $asked++ === 0);
		});
		$policy = new Policy($this->config, $groupManager, $this->subAdmin);
		$stored = $policy->store(Policy::MODE_INCLUDE_GROUPS, ['g1', 'g3'], true);
		$this->assertSame(['mode' => Policy::MODE_INCLUDE_GROUPS, 'groups' => ['g1'], 'allowGroupAdminTargets' => true], $stored);
		$this->assertSame('["g1"]', $this->appConfig['impersonate_include_groups_list']);
	}

	public function testTheDeletionOfAGroupSwitchesOffTheConsentThatMentionsIt(): void {
		// switching off can never broaden the delegation, whatever an administrator saved meanwhile
		$logger = $this->createMock(ILogger::class);
		$logger->expects($this->once())->method('warning')->with($this->stringContains('was switched off'));
		$policy = new Policy($this->config, $this->groupManager, $this->subAdmin, null, $logger);
		$policy->store(Policy::MODE_INCLUDE_GROUPS, ['g1', 'g2'], true);
		$policy->forgetGroup('g1');
		$this->assertSame(['mode' => Policy::MODE_INCLUDE_GROUPS, 'groups' => ['g2'], 'allowGroupAdminTargets' => false], $policy->describe());
		$this->assertSame('false', $this->appConfig['impersonate_allow_groupadmin_targets']);
		// a consent that does not mention the group stays
		$policy->store(Policy::MODE_INCLUDE_GROUPS, ['g2'], true);
		$policy->forgetGroup('g3');
		$this->assertTrue($policy->allowsGroupAdminTargets());
	}

	public function testTheDeletionOfAGroupWorksOnTheValuesAsTheDatabaseHasThemNow(): void {
		// This request loaded the list [g1,g2,g3] with a consent for it; meanwhile an administrator
		// saved [g1] without a consent. Deleting g3 must not bring back what was saved over.
		$this->appConfig['impersonate_include_groups'] = 'true';
		$this->appConfig['impersonate_include_groups_list'] = '["g1","g2","g3"]';
		$this->appConfig['impersonate_allow_groupadmin_targets'] = '{"mode":"include_groups","groups":["g1","g2","g3"]}';
		$rows = [
			['configkey' => 'impersonate_include_groups', 'configvalue' => 'true'],
			['configkey' => 'impersonate_include_groups_list', 'configvalue' => '["g1"]'],
			['configkey' => 'impersonate_allow_groupadmin_targets', 'configvalue' => 'false'],
		];
		$query = $this->createMock(IQueryBuilder::class);
		foreach (['select', 'addSelect', 'from', 'where'] as $method) {
			$query->method($method)->willReturnSelf();
		}
		$query->method('expr')->willReturn($this->createMock(IExpressionBuilder::class));
		$query->method('execute')->willReturnCallback(function () use ($rows) {
			return new class($rows) {
				/** @var array */
				private $rows;

				public function __construct(array $rows) {
					$this->rows = $rows;
				}

				public function fetchAllAssociative(): array {
					return $this->rows;
				}

				public function free(): void {
				}
			};
		});
		$connection = $this->createMock(IDBConnection::class);
		$connection->method('getQueryBuilder')->willReturn($query);
		$policy = new Policy($this->config, $this->groupManager, $this->subAdmin, $connection);
		$this->written = [];
		$policy->forgetGroup('g3');
		// the list as the database has it does not contain g3, the consent there is off: nothing to write
		$this->assertSame([], $this->written);
		$policy->forgetGroup('g1');
		$this->assertSame([['impersonate_include_groups_list', '[]']], $this->written);
	}

	/**
	 * The writes one store() makes, starting from the given stored values.
	 *
	 * @return array[] [key, value]
	 */
	private function writesOf(array $start, array $policy): array {
		$this->appConfig = $start;
		$this->written = [];
		$this->policy()->store($policy['mode'], $policy['groups'], $policy['allowGroupAdminTargets']);
		return $this->written;
	}

	/**
	 * @return array{mode: string, groups: string[], allowGroupAdminTargets: bool} what a reader applies
	 */
	private function seen(array $values): array {
		$this->appConfig = $values;
		return $this->policy()->describe();
	}

	/**
	 * May a group admin of $gid impersonate a member of it (who is a group admin or not)?
	 */
	private static function permits(array $policy, string $gid, bool $targetIsGroupAdmin): bool {
		$group = $policy['mode'] === Policy::MODE_ALL_GROUP_ADMINS
			|| ($policy['mode'] === Policy::MODE_INCLUDE_GROUPS && \in_array($gid, $policy['groups'], true));
		return $group && (!$targetIsGroupAdmin || $policy['allowGroupAdminTargets']);
	}

	/**
	 * Every way to merge two sequences, each one in its own order.
	 *
	 * @return \Generator<array>
	 */
	private static function interleavings(array $a, array $b): \Generator {
		if ($a === [] || $b === []) {
			yield \array_merge($a, $b);
			return;
		}
		foreach (self::interleavings(\array_slice($a, 1), $b) as $rest) {
			yield \array_merge([$a[0]], $rest);
		}
		foreach (self::interleavings($a, \array_slice($b, 1)) as $rest) {
			yield \array_merge([$b[0]], $rest);
		}
	}

	public static function overlappingSavesProvider(): array {
		$policies = [
			'admins' => ['mode' => Policy::MODE_ADMINS, 'groups' => [], 'allowGroupAdminTargets' => false],
			'admins+targets' => ['mode' => Policy::MODE_ADMINS, 'groups' => [], 'allowGroupAdminTargets' => true],
			'all' => ['mode' => Policy::MODE_ALL_GROUP_ADMINS, 'groups' => [], 'allowGroupAdminTargets' => false],
			'all+targets' => ['mode' => Policy::MODE_ALL_GROUP_ADMINS, 'groups' => [], 'allowGroupAdminTargets' => true],
			'g1' => ['mode' => Policy::MODE_INCLUDE_GROUPS, 'groups' => ['g1'], 'allowGroupAdminTargets' => false],
			'g2+targets' => ['mode' => Policy::MODE_INCLUDE_GROUPS, 'groups' => ['g2'], 'allowGroupAdminTargets' => true],
		];
		$cases = [];
		foreach ($policies as $fromName => $from) {
			foreach ($policies as $firstName => $first) {
				foreach ($policies as $secondName => $second) {
					if ($firstName < $secondName) {
						$cases["$fromName, then $firstName and $secondName at once"] = [$from, $first, $second];
					}
				}
			}
		}
		return $cases;
	}

	/**
	 * Two administrators save different policies at the same moment: whatever order their writes
	 * reach the database in, what a reader applies is never broader than one of the policies
	 * (while they are written: than one of them or the one before).
	 *
	 * @dataProvider overlappingSavesProvider
	 */
	public function testOverlappingSavesNeverLeaveABroaderDelegation(array $from, array $first, array $second): void {
		$this->writesOf([], $from);
		$start = $this->appConfig;
		$this->assertSame($from, $this->seen($start));
		$writesOfFirst = $this->writesOf($start, $first);
		$writesOfSecond = $this->writesOf($start, $second);
		$orders = 0;
		foreach (self::interleavings($writesOfFirst, $writesOfSecond) as $order) {
			$orders++;
			$values = $start;
			foreach ($order as $step => [$key, $value]) {
				$values[$key] = $value;
				$seen = $this->seen($values);
				$done = $step === \count($order) - 1;
				foreach ($this->existingGroups as $gid) {
					foreach ([false, true] as $targetIsGroupAdmin) {
						$this->assertTrue(
							!self::permits($seen, $gid, $targetIsGroupAdmin)
								|| (!$done && self::permits($from, $gid, $targetIsGroupAdmin))
								|| self::permits($first, $gid, $targetIsGroupAdmin)
								|| self::permits($second, $gid, $targetIsGroupAdmin),
							"$gid, group admin as target: " . \var_export($targetIsGroupAdmin, true)
								. ', seen: ' . \json_encode($seen) . ', values: ' . \json_encode($values)
						);
					}
				}
			}
		}
		$this->assertGreaterThan(1, $orders);
	}
}
