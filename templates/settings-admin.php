<?php
/**
 * Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
 * Maintained by Marek Królikowski (TaKeN): https://github.com/takenek/impersonate
 * Modified on 2026-11-26 and 2026-11-27 by Marek Królikowski (TaKeN): ownCloud 11.1 support and
 * security hardening, see CHANGELOG.md. SPDX-License-Identifier: AGPL-3.0-only
 * See LICENSE and COPYRIGHT.
 *
 * Based on the ownCloud "impersonate" app (https://github.com/owncloud/impersonate):
 * * Copyright (C) 2015-2023 ownCloud GmbH and contributors
 */
/** @var array $_ */
/** @var \OCP\IL10N $l */
script('impersonate', 'settings-admin');
style('impersonate', 'settings-admin');
$groupAdminsDisabled = !$_['groupAdminFeatureEnabled'];
$onlyAdmins = !$_['allGroupAdmins'] && !$_['includeGroups'];
// The group picker of core separates the ids with "|": a group whose id contains it can not
// be shown there. Such groups stay in the list (the page sends them back unchanged).
$pickableGroups = [];
$lockedGroups = [];
foreach ($_['includedGroups'] as $gid) {
	if (\strpos($gid, '|') === false) {
		$pickableGroups[] = $gid;
	} else {
		$lockedGroups[] = $gid;
	}
}
?>
<div class="section" id="impersonateTemplateSettings">

	<h2><?php p($l->t('Impersonate Settings'));?></h2>

	<?php if ($groupAdminsDisabled): ?>
	<p class="settings-hint" id="impersonateGroupAdminsDisabledHint">
		<?php p($l->t('The group admin feature of this server is disabled (config.php: \'allow_subadmins\' => false), so only administrators can impersonate users. Set \'allow_subadmins\' => true to use the group admin options.'));?>
	</p>
	<?php endif; ?>

	<p class="<?php if (!$_['appEnabled']) {
		p('hidden');
	}?>">
		<input type="radio" name="groupadmins" id="impersonateNoGroupAdmins" class="radio"
			<?php if ($onlyAdmins) {
				print_unescaped('checked="checked"');
			} ?> />
		<label for="impersonateNoGroupAdmins"><?php p($l->t('Only an administrator is allowed to impersonate users'))?></label><br/>

		<input type="radio" name="groupadmins" id="impersonateAllGroupAdmins" class="radio"
			<?php if ($_['allGroupAdmins']) {
				print_unescaped('checked="checked"');
			} ?> />
		<label for="impersonateAllGroupAdmins"><?php p($l->t('Allow all group admins to impersonate users within the groups they are admins of'))?></label><br/>

		<input type="radio" name="groupadmins" id="impersonateIncludeGroups" class="radio"
			<?php if ($_['includeGroups']) {
				print_unescaped('checked="checked"');
			} ?> />
		<label for="impersonateIncludeGroups"><?php p($l->t('Allow group admins of specific groups to impersonate the users within those groups'));?></label><br/>

	</p>
	<p id="selectIncludedGroups" class="indent <?php if (!$_['includeGroups']) {
		p('hidden');
	} ?>">
		<?php // the value is what the group picker of core expects, the lists themselves travel as JSON?>
		<input name="impersonate_include_groups_list" type="hidden" id="includedGroups"
			value="<?php p(\implode('|', $pickableGroups)); ?>"
			data-groups="<?php p((string)\json_encode($pickableGroups)); ?>"
			data-locked-groups="<?php p((string)\json_encode($lockedGroups)); ?>" style="width: 400px"/>
		<br />
		<?php if ($lockedGroups !== []): ?>
		<em id="impersonateLockedGroups"><?php p($l->t('Also in the list, but not editable here because their id contains "|": %s', [\implode(', ', $lockedGroups)]));?></em>
		<?php endif; ?>
	</p>
	<p class="<?php if (!$_['appEnabled']) {
		p('hidden');
	}?>">
		<input type="checkbox" id="impersonateGroupAdminTargets" class="checkbox"
			<?php if ($_['allowGroupAdminTargets']) {
				print_unescaped('checked="checked"');
			} ?> />
		<label for="impersonateGroupAdminTargets"><?php p($l->t('Allow group admins to impersonate members who are group admins themselves'));?></label><br/>
		<em><?php p($l->t('Such a member may administer other groups. The impersonating group admin would act with those rights as well.'));?></em>
	</p>
	<p class="settings-hint" id="impersonateMaxDurationHint">
		<?php if ($_['maxDurationMinutes'] > 0) {
			p($l->t('An impersonation ends after %s minutes at the latest (app config "max_duration_minutes").', [$_['maxDurationMinutes']]));
		} else {
			p($l->t('The duration of an impersonation is not limited (app config "max_duration_minutes" is 0).'));
		} ?>
	</p>
	<?php if ($_['forbiddenPrefixes'] !== []): ?>
	<p class="settings-hint" id="impersonateForbiddenPrefixes">
		<?php p($l->t('Refused during an impersonation in addition to the built-in list (app config "forbidden_prefixes"): %s', [\implode(' ', $_['forbiddenPrefixes'])]));?>
	</p>
	<?php endif; ?>
	<?php if ($_['ignoredForbiddenPrefixes'] !== []): ?>
	<p class="settings-hint" id="impersonateIgnoredForbiddenPrefixes">
		<strong><?php p($l->t('Entries of the app config "forbidden_prefixes" that are not a path prefix like "/apps/someapp/" and are ignored: %s', [\implode(' ', $_['ignoredForbiddenPrefixes'])]));?></strong>
	</p>
	<?php endif; ?>

</div>
