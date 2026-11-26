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

use OC\SubAdmin;
use OCP\IConfig;
use OCP\IGroupManager;
use OCP\IUser;

/**
 * Single source of truth for "who may impersonate whom".
 *
 * Used when an impersonation is started, on every request while an
 * impersonation is active (so that revoked permissions end it) and to
 * build the data the users page needs.
 */
class Policy {
	public const APP = 'impersonate';

	/** an admin may impersonate anyone (but not themselves) */
	public const ERROR_CANNOT_IMPERSONATE = 'cannotImpersonate';
	public const ERROR_ADMIN_TARGET = 'cannotImpersonateAdminUser';
	public const ERROR_DISABLED_TARGET = 'userDisabled';
	public const ERROR_NEVER_LOGGED_IN = 'userNeverLoggedIn';

	/** @var IConfig */
	private $config;
	/** @var IGroupManager */
	private $groupManager;
	/** @var SubAdmin */
	private $subAdmin;

	public function __construct(IConfig $config, IGroupManager $groupManager, SubAdmin $subAdmin) {
		$this->config = $config;
		$this->groupManager = $groupManager;
		$this->subAdmin = $subAdmin;
	}

	/**
	 * ownCloud 11 disables the whole group admin feature unless the system
	 * config "allow_subadmins" is true. Older versions have no switch.
	 */
	public function isGroupAdminFeatureEnabled(): bool {
		if (\method_exists($this->subAdmin, 'isEnabled')) {
			return $this->subAdmin->isEnabled();
		}
		return true;
	}

	public function isAllGroupAdminsMode(): bool {
		return $this->config->getAppValue(self::APP, 'impersonate_all_groupadmins', 'false') === 'true';
	}

	public function isIncludeGroupsMode(): bool {
		return !$this->isAllGroupAdminsMode()
			&& $this->config->getAppValue(self::APP, 'impersonate_include_groups', 'false') === 'true';
	}

	/**
	 * Configured group ids for the "specific groups" mode, always a list of strings.
	 *
	 * @return string[]
	 */
	public function getIncludedGroups(): array {
		return self::decodeGroupList(
			$this->config->getAppValue(self::APP, 'impersonate_include_groups_list', '[]')
		);
	}

	/**
	 * Robustly decode a JSON list of group ids. Anything that is not a JSON
	 * array of non-empty strings is ignored.
	 *
	 * @param mixed $raw
	 * @return string[]
	 */
	public static function decodeGroupList($raw): array {
		if (!\is_string($raw) || $raw === '') {
			return [];
		}
		$decoded = \json_decode($raw, true);
		if (!\is_array($decoded) || !\array_is_list($decoded)) {
			return [];
		}
		$groups = [];
		foreach ($decoded as $group) {
			if (\is_string($group) && $group !== '') {
				$groups[] = $group;
			}
		}
		return \array_values(\array_unique($groups));
	}

	public function isAdmin(IUser $user): bool {
		return $this->groupManager->isAdmin($user->getUID());
	}

	/**
	 * Is the user a group admin whose impersonation right is currently enabled?
	 */
	public function isDelegatedGroupAdmin(IUser $user): bool {
		if (!$this->isGroupAdminFeatureEnabled()) {
			return false;
		}
		if (!$this->isAllGroupAdminsMode() && !$this->isIncludeGroupsMode()) {
			return false;
		}
		return $this->subAdmin->isSubAdmin($user);
	}

	/**
	 * May the user impersonate anybody at all (without looking at a target)?
	 */
	public function mayImpersonateAnyone(IUser $user): bool {
		return $this->isAdmin($user) || $this->isDelegatedGroupAdmin($user);
	}

	/**
	 * Groups whose members the (group admin) user may impersonate.
	 *
	 * @return string[] group ids
	 */
	public function getImpersonableGroupIds(IUser $groupAdmin): array {
		if (!$this->isDelegatedGroupAdmin($groupAdmin)) {
			return [];
		}
		$adminOf = [];
		foreach ($this->subAdmin->getSubAdminsGroups($groupAdmin) as $group) {
			$adminOf[] = $group->getGID();
		}
		if ($this->isAllGroupAdminsMode()) {
			return $adminOf;
		}
		return \array_values(\array_intersect($this->getIncludedGroups(), $adminOf));
	}

	/**
	 * Uids of administrators that are members of one of the given groups
	 * (used to hide the impersonate icon for group admins).
	 *
	 * @param string[] $groupIds
	 * @return string[]
	 */
	public function getAdminUidsInGroups(array $groupIds): array {
		if ($groupIds === []) {
			return [];
		}
		$adminGroup = $this->groupManager->get('admin');
		if ($adminGroup === null) {
			return [];
		}
		$uids = [];
		foreach ($adminGroup->getUsers() as $admin) {
			foreach ($groupIds as $gid) {
				if ($this->groupManager->isInGroup($admin->getUID(), $gid)) {
					$uids[] = $admin->getUID();
					break;
				}
			}
		}
		return $uids;
	}

	/**
	 * Check whether $impersonator may impersonate $target.
	 * This does not look at session state (nested impersonation) or at the
	 * target's last login.
	 *
	 * @return string|null null if allowed, otherwise an error code
	 */
	public function check(IUser $impersonator, IUser $target): ?string {
		if (\strtolower($impersonator->getUID()) === \strtolower($target->getUID())) {
			return self::ERROR_CANNOT_IMPERSONATE;
		}
		if (!$impersonator->isEnabled()) {
			return self::ERROR_CANNOT_IMPERSONATE;
		}

		if ($this->isAdmin($impersonator)) {
			if (!$target->isEnabled()) {
				return self::ERROR_DISABLED_TARGET;
			}
			return null;
		}

		// group admins: never an admin, only enabled members of the allowed groups
		if ($this->groupManager->isAdmin($target->getUID())) {
			return self::ERROR_ADMIN_TARGET;
		}
		if (!$target->isEnabled()) {
			return self::ERROR_DISABLED_TARGET;
		}
		foreach ($this->getImpersonableGroupIds($impersonator) as $gid) {
			if ($this->groupManager->isInGroup($target->getUID(), $gid)) {
				return null;
			}
		}
		return self::ERROR_CANNOT_IMPERSONATE;
	}
}
