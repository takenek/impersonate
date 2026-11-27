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
use OCP\IConfig;
use OCP\IGroup;
use OCP\IGroupManager;
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
		$this->assertSame('true', $this->appConfig['impersonate_allow_groupadmin_targets']);
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
}
