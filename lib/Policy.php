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

	public const MODE_ADMINS = 'admins';
	public const MODE_ALL_GROUP_ADMINS = 'all_groupadmins';
	public const MODE_INCLUDE_GROUPS = 'include_groups';

	/** default of the app config "max_duration_minutes" */
	public const DEFAULT_MAX_DURATION_MINUTES = 60;

	/**
	 * Leading path segments that only select an entry point or an API version:
	 * the same operation is reached with and without them.
	 */
	public const ENTRY_POINT_SEGMENTS = ['index.php', 'ocs', 'v1.php', 'v2.php'];

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

	/**
	 * May group admins impersonate members who are group admins themselves?
	 * Off by default: such a member can act on groups that were not delegated to
	 * the impersonator.
	 */
	public function allowsGroupAdminTargets(): bool {
		return $this->config->getAppValue(self::APP, 'impersonate_allow_groupadmin_targets', 'false') === 'true';
	}

	/**
	 * May an impersonation also be started by a request that authenticates
	 * itself (HTTP Basic, a token) or from a session that was created by such
	 * a request? Off by default (app config "allow_start_with_credentials"):
	 * the platform does not ask such requests for the CSRF token, and their
	 * sessions are not the result of an interactive login. For instances where
	 * every request of a browser carries credentials (authentication by a
	 * proxy or by the web server).
	 */
	public function allowsStartWithCredentials(): bool {
		return $this->config->getAppValue(self::APP, 'allow_start_with_credentials', 'false') === 'true';
	}

	/**
	 * Maximum duration of an impersonation in seconds, 0 = no limit. App config
	 * "max_duration_minutes" (default 60); anything that is not a non-negative
	 * integer counts as the default, so a broken value never removes the limit.
	 */
	public function getMaxDuration(): int {
		$raw = $this->config->getAppValue(self::APP, 'max_duration_minutes', (string)self::DEFAULT_MAX_DURATION_MINUTES);
		$minutes = \is_string($raw) && \preg_match('/^\d{1,6}$/', $raw) === 1
			? (int)$raw
			: self::DEFAULT_MAX_DURATION_MINUTES;
		return 60 * $minutes;
	}

	/**
	 * @param int|null $start time the impersonation started (null: unknown)
	 */
	public function hasExceededMaxDuration(?int $start, ?int $now = null): bool {
		$max = $this->getMaxDuration();
		if ($max === 0) {
			return false;
		}
		// an impersonation without a known start can not be bounded: it counts as expired
		return $start === null || ($now ?? \time()) - $start > $max;
	}

	/**
	 * Path prefixes (as the router sees them, e.g. "/apps/someapp/") that operators
	 * forbid during an impersonation in addition to the built-in list of
	 * ImpersonationGuard. App config "forbidden_prefixes": a JSON list of strings.
	 * A missing trailing slash is added and a leading entry point ("/index.php",
	 * "/ocs/v1.php") is dropped. Entries that are not a plain path are ignored
	 * (getIgnoredForbiddenPrefixes() names them for the admin page).
	 *
	 * @return string[] lower-case prefixes with a leading and a trailing slash
	 */
	public function getExtraForbiddenPrefixes(): array {
		return $this->readForbiddenPrefixes()[0];
	}

	/**
	 * @return string[] entries of the app config "forbidden_prefixes" that are not used; the whole
	 *                  value if it is not a JSON list of strings
	 */
	public function getIgnoredForbiddenPrefixes(): array {
		return $this->readForbiddenPrefixes()[1];
	}

	/**
	 * @return array{0: string[], 1: string[]} used prefixes, ignored entries
	 */
	private function readForbiddenPrefixes(): array {
		$raw = $this->config->getAppValue(self::APP, 'forbidden_prefixes', '[]');
		$decoded = \is_string($raw) ? \json_decode($raw === '' ? '[]' : $raw, true) : null;
		if (!\is_array($decoded) || !\array_is_list($decoded)) {
			return [[], [\is_string($raw) ? $raw : '']];
		}
		$prefixes = [];
		$ignored = [];
		foreach ($decoded as $entry) {
			$prefix = null;
			if (\is_string($entry) && \preg_match('%^/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*/?\z%', $entry) === 1) {
				// the guard compares paths without their entry point
				$segments = \explode('/', \strtolower(\trim($entry, '/')));
				while ($segments !== [] && \in_array($segments[0], self::ENTRY_POINT_SEGMENTS, true)) {
					\array_shift($segments);
				}
				if ($segments !== []) {
					$prefix = '/' . \implode('/', $segments) . '/';
				}
			}
			if ($prefix !== null) {
				$prefixes[] = $prefix;
			} else {
				$ignored[] = \is_string($entry) ? $entry : (string)\json_encode($entry);
			}
		}
		return [\array_values(\array_unique($prefixes)), $ignored];
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
	 * Uids of group admins that are members of one of the given groups (used to
	 * hide the impersonate icon for group admins unless such targets are allowed).
	 *
	 * @param string[] $groupIds
	 * @return string[]
	 */
	public function getGroupAdminUidsInGroups(array $groupIds): array {
		if ($groupIds === [] || $this->allowsGroupAdminTargets()) {
			return [];
		}
		$uids = [];
		foreach ($this->subAdmin->getAllSubAdmins() as $entry) {
			$user = \is_array($entry) ? ($entry['user'] ?? null) : null;
			if (!$user instanceof IUser || isset($uids[$user->getUID()])) {
				continue;
			}
			foreach ($groupIds as $gid) {
				if ($this->groupManager->isInGroup($user->getUID(), $gid)) {
					$uids[$user->getUID()] = true;
					break;
				}
			}
		}
		return \array_map('strval', \array_keys($uids));
	}

	/**
	 * The stored delegation policy as the server applies it.
	 *
	 * @return array{mode: string, groups: string[], allowGroupAdminTargets: bool}
	 */
	public function describe(): array {
		if ($this->isAllGroupAdminsMode()) {
			$mode = self::MODE_ALL_GROUP_ADMINS;
		} elseif ($this->isIncludeGroupsMode()) {
			$mode = self::MODE_INCLUDE_GROUPS;
		} else {
			$mode = self::MODE_ADMINS;
		}
		return [
			'mode' => $mode,
			'groups' => $mode === self::MODE_INCLUDE_GROUPS ? $this->getIncludedGroups() : [],
			'allowGroupAdminTargets' => $this->allowsGroupAdminTargets(),
		];
	}

	/**
	 * Validate and store the whole delegation policy. Only existing groups are
	 * kept. The values are written in an order in which a failure in between
	 * never leaves a broader delegation than the previous or the requested one.
	 *
	 * @param mixed[] $groups
	 * @return array{mode: string, groups: string[], allowGroupAdminTargets: bool} the stored policy
	 * @throws \InvalidArgumentException for an unknown mode
	 */
	public function store(string $mode, array $groups, bool $allowGroupAdminTargets): array {
		if (!\in_array($mode, [self::MODE_ADMINS, self::MODE_ALL_GROUP_ADMINS, self::MODE_INCLUDE_GROUPS], true)) {
			throw new \InvalidArgumentException('Unknown delegation mode');
		}
		$valid = [];
		if ($mode === self::MODE_INCLUDE_GROUPS) {
			foreach ($groups as $gid) {
				if (\is_string($gid) && $gid !== '' && !\in_array($gid, $valid, true) && $this->groupManager->groupExists($gid)) {
					$valid[] = $gid;
				}
			}
		}
		if (!$allowGroupAdminTargets) {
			// narrowing first
			$this->config->setAppValue(self::APP, 'impersonate_allow_groupadmin_targets', 'false');
		}
		$this->config->setAppValue(self::APP, 'impersonate_all_groupadmins', $mode === self::MODE_ALL_GROUP_ADMINS ? 'true' : 'false');
		$this->config->setAppValue(self::APP, 'impersonate_include_groups_list', (string)\json_encode($valid));
		$this->config->setAppValue(self::APP, 'impersonate_include_groups', $mode === self::MODE_INCLUDE_GROUPS ? 'true' : 'false');
		if ($allowGroupAdminTargets) {
			$this->config->setAppValue(self::APP, 'impersonate_allow_groupadmin_targets', 'true');
		}
		return $this->describe();
	}

	/**
	 * A group was deleted: its id must not stay in the delegation list, a group
	 * created later under the same id would inherit the delegation.
	 */
	public function forgetGroup(string $gid): void {
		$groups = $this->getIncludedGroups();
		if (\in_array($gid, $groups, true)) {
			$this->config->setAppValue(
				self::APP,
				'impersonate_include_groups_list',
				(string)\json_encode(\array_values(\array_diff($groups, [$gid])))
			);
		}
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
				// ... and no group admin either (who may administer groups that were not
				// delegated to the impersonator) unless that is explicitly allowed
				if (!$this->allowsGroupAdminTargets() && $this->subAdmin->isSubAdmin($target)) {
					return self::ERROR_ADMIN_TARGET;
				}
				return null;
			}
		}
		return self::ERROR_CANNOT_IMPERSONATE;
	}
}
