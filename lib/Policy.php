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
use OCP\IDBConnection;
use OCP\IGroupManager;
use OCP\ILogger;
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

	private const KEY_GROUP_LIST = 'impersonate_include_groups_list';
	/** "false", "true" (a consent without binding) or the delegation the consent was given for (JSON) */
	private const KEY_GROUP_ADMIN_TARGETS = 'impersonate_allow_groupadmin_targets';

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
	/** @var IDBConnection|null for reading values as the database has them now (forgetGroup()) */
	private $connection;
	/** @var ILogger|null */
	private $logger;

	public function __construct(
		IConfig $config,
		IGroupManager $groupManager,
		SubAdmin $subAdmin,
		?IDBConnection $connection = null,
		?ILogger $logger = null
	) {
		$this->config = $config;
		$this->groupManager = $groupManager;
		$this->subAdmin = $subAdmin;
		$this->connection = $connection;
		$this->logger = $logger;
	}

	/**
	 * ownCloud 11 disables the whole group admin feature unless the system
	 * config "allow_subadmins" is true. A platform without that switch is not
	 * one the app supports: then the feature counts as disabled (only
	 * administrators can impersonate).
	 */
	public function isGroupAdminFeatureEnabled(): bool {
		if (\method_exists($this->subAdmin, 'isEnabled')) {
			return $this->subAdmin->isEnabled();
		}
		return false;
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
			$this->config->getAppValue(self::APP, self::KEY_GROUP_LIST, '[]')
		);
	}

	/**
	 * Robustly decode a JSON list of group ids. Anything that is not a JSON
	 * array of non-empty strings is ignored (a JSON object is no list, whatever
	 * its keys are).
	 *
	 * @param mixed $raw
	 * @return string[]
	 */
	public static function decodeGroupList($raw): array {
		if (!\is_string($raw) || $raw === '') {
			return [];
		}
		// objects stay objects: only a JSON array becomes a PHP array
		$decoded = \json_decode($raw);
		if (!\is_array($decoded)) {
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
	 *
	 * The admin page stores this consent together with the mode and the groups
	 * it was given for (store()): it only applies while exactly that delegation
	 * is stored. The four values of the policy are written one after the other,
	 * so two saves that overlap could otherwise leave the mode of one with the
	 * consent of the other - a delegation broader than either administrator
	 * approved. The value "true" (set with occ, or by a version before 1.0.4)
	 * is a consent without that binding.
	 */
	public function allowsGroupAdminTargets(): bool {
		$raw = $this->config->getAppValue(self::APP, self::KEY_GROUP_ADMIN_TARGETS, 'false');
		if ($raw === 'true') {
			return true;
		}
		$binding = self::decodeTargetsBinding($raw);
		if ($binding === null) {
			return false;
		}
		$mode = $this->mode();
		return $binding['mode'] === $mode
			&& self::sameGroups($binding['groups'], $mode === self::MODE_INCLUDE_GROUPS ? $this->getIncludedGroups() : []);
	}

	/**
	 * @param mixed $raw
	 * @return array{mode: string, groups: string[]}|null the delegation a stored consent was given for
	 */
	private static function decodeTargetsBinding($raw): ?array {
		$decoded = \is_string($raw) && $raw !== '' ? \json_decode($raw, true) : null;
		if (!\is_array($decoded) || !\is_string($decoded['mode'] ?? null) || !\is_array($decoded['groups'] ?? null)
			|| !\array_is_list($decoded['groups'])
		) {
			return null;
		}
		foreach ($decoded['groups'] as $gid) {
			if (!\is_string($gid)) {
				return null;
			}
		}
		return ['mode' => $decoded['mode'], 'groups' => $decoded['groups']];
	}

	/**
	 * @param string[] $a
	 * @param string[] $b
	 */
	private static function sameGroups(array $a, array $b): bool {
		$a = \array_values(\array_unique($a));
		$b = \array_values(\array_unique($b));
		\sort($a, SORT_STRING);
		\sort($b, SORT_STRING);
		return $a === $b;
	}

	/**
	 * @param string[] $groups
	 */
	private static function targetsBinding(string $mode, array $groups): string {
		return \json_encode(['mode' => $mode, 'groups' => \array_values($groups)], JSON_THROW_ON_ERROR);
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
	 * "max_duration_minutes" (default 60): a positive whole number of minutes
	 * (white space around it does not matter); only exactly "0" removes the limit;
	 * anything else counts as the default, so a broken value never removes the
	 * limit (and a number with a line break after it is not made longer).
	 */
	public function getMaxDuration(): int {
		$raw = $this->config->getAppValue(self::APP, 'max_duration_minutes', (string)self::DEFAULT_MAX_DURATION_MINUTES);
		if ($raw === '0') {
			return 0;
		}
		$value = \is_string($raw) ? \trim($raw) : '';
		$minutes = \preg_match('/^\d{1,6}\z/', $value) === 1 && (int)$value > 0
			? (int)$value
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
		// A JSON object whose keys are 0, 1, 2, ... is taken as the list it describes: what was
		// refused up to now is refused after an update as well (unlike the group list, where a
		// value that is not a JSON array delegates nothing).
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
		$mode = $this->mode();
		return [
			'mode' => $mode,
			'groups' => $mode === self::MODE_INCLUDE_GROUPS ? $this->getIncludedGroups() : [],
			'allowGroupAdminTargets' => $this->allowsGroupAdminTargets(),
		];
	}

	/**
	 * Validate and store the whole delegation policy. Only existing groups are
	 * kept. The values are written in an order in which a failure in between
	 * never leaves a broader delegation than the previous or the requested one;
	 * the consent to group admins as targets is bound to the delegation it is
	 * given for (allowsGroupAdminTargets()), so that two saves that overlap
	 * never leave a delegation broader than one of them. A consent given in
	 * the mode "administrators only" (where group admins impersonate nobody)
	 * does not apply in the mode chosen later.
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
		$targets = $allowGroupAdminTargets;
		if (!$targets) {
			// narrowing first
			$this->config->setAppValue(self::APP, self::KEY_GROUP_ADMIN_TARGETS, 'false');
		}
		$this->config->setAppValue(self::APP, 'impersonate_all_groupadmins', $mode === self::MODE_ALL_GROUP_ADMINS ? 'true' : 'false');
		$this->config->setAppValue(self::APP, self::KEY_GROUP_LIST, (string)\json_encode($valid));
		$this->config->setAppValue(self::APP, 'impersonate_include_groups', $mode === self::MODE_INCLUDE_GROUPS ? 'true' : 'false');
		if ($targets) {
			$this->config->setAppValue(self::APP, self::KEY_GROUP_ADMIN_TARGETS, self::targetsBinding($mode, $valid));
		}
		// A group deleted while this was stored must not stay in the list (forgetGroup() may have
		// run before the list above was written): a group created later under the same id would
		// inherit the delegation. As far as this process can tell: the group manager may answer
		// from what it loaded for this request.
		$existing = \array_values(\array_filter($valid, function (string $gid): bool {
			return $this->groupManager->groupExists($gid);
		}));
		if ($existing !== $valid) {
			$this->config->setAppValue(self::APP, self::KEY_GROUP_LIST, (string)\json_encode($existing));
			if ($targets) {
				$this->config->setAppValue(self::APP, self::KEY_GROUP_ADMIN_TARGETS, self::targetsBinding($mode, $existing));
			}
		}
		return $this->describe();
	}

	/**
	 * A group was deleted: its id must not stay in the delegation list, a group
	 * created later under the same id would inherit the delegation. The values
	 * are read as the database has them now, not as this request loaded them (an
	 * administrator may have saved the policy meanwhile). A consent to group
	 * admins as targets that was given for a list with the group is switched off
	 * (switching off can never broaden the delegation, whatever was saved in
	 * between); the administrator saves the policy again to keep it.
	 */
	public function forgetGroup(string $gid): void {
		$groups = self::decodeGroupList($this->currentValue(self::KEY_GROUP_LIST, '[]'));
		if (\in_array($gid, $groups, true)) {
			$this->config->setAppValue(
				self::APP,
				self::KEY_GROUP_LIST,
				(string)\json_encode(\array_values(\array_diff($groups, [$gid])))
			);
		}
		$binding = self::decodeTargetsBinding($this->currentValue(self::KEY_GROUP_ADMIN_TARGETS, 'false'));
		if ($binding !== null && \in_array($gid, $binding['groups'], true)) {
			$this->config->setAppValue(self::APP, self::KEY_GROUP_ADMIN_TARGETS, 'false');
			if ($this->logger !== null) {
				$this->logger->warning(
					'The option to let group admins impersonate members who are group admins themselves was switched off: it was given for the deleted group "{group}". Save the impersonation policy again to keep it.',
					['app' => self::APP, 'group' => $gid]
				);
			}
		}
	}

	/**
	 * A value of the app as the database has it now (as this request loaded it if there is no
	 * database connection, e.g. in unit tests).
	 */
	private function currentValue(string $key, string $default): string {
		if ($this->connection === null) {
			return (string)$this->config->getAppValue(self::APP, $key, $default);
		}
		$value = ActiveImpersonations::freshAppValues($this->connection)[$key] ?? null;
		return \is_string($value) ? $value : $default;
	}

	/**
	 * @return string self::MODE_* as the stored values say it
	 */
	private function mode(): string {
		if ($this->isAllGroupAdminsMode()) {
			return self::MODE_ALL_GROUP_ADMINS;
		}
		if ($this->isIncludeGroupsMode()) {
			return self::MODE_INCLUDE_GROUPS;
		}
		return self::MODE_ADMINS;
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
