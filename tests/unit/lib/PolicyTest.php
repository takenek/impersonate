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
}
