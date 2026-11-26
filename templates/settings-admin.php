<?php
/**
 * Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
 * Maintained by Marek Królikowski (TaKeN): https://github.com/takenek/impersonate
 * Modified on 2026-11-26 by Marek Królikowski (TaKeN): ownCloud 11.1 support and security
 * hardening, see CHANGELOG.md. SPDX-License-Identifier: AGPL-3.0-only
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
		<input name="impersonate_include_groups_list" type="hidden" id="includedGroups"
			value="<?php p(\implode('|', $_['includedGroups'])); ?>" style="width: 400px"/>
		<br />
	</p>

</div>
