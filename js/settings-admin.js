/**
 * Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
 * Modified on 2026-11-26 and 2026-11-27 by Marek Królikowski (TaKeN), see CHANGELOG.md.
 * Based on the ownCloud "impersonate" app, Copyright (C) 2015-2023 ownCloud GmbH and contributors.
 * SPDX-License-Identifier: AGPL-3.0-only - see LICENSE and COPYRIGHT.
 */
$(document).ready(function () {
	var $section = $('#impersonateTemplateSettings');
	if (!$section.length) {
		return;
	}
	var $radios = $section.find('input[name="groupadmins"]');
	var $groupAdminTargets = $('#impersonateGroupAdminTargets');
	var $groups = $('#includedGroups');
	// groups the group picker can not show (their id contains its separator "|"): sent back unchanged
	var lockedGroups = parseList($groups.attr('data-locked-groups'));
	var groups = lockedGroups.concat(parseList($groups.attr('data-groups')));
	var pending = false;
	var dirty = false;
	var reloading = false;

	function parseList(json) {
		try {
			var list = JSON.parse(json || '[]');
			return _.isArray(list) ? _.map(list, String) : [];
		} catch (e) {
			return [];
		}
	}

	function reload() {
		// nothing is sent anymore: the page shows what the server has once it is back
		reloading = true;
		dirty = false;
		window.location.reload();
	}

	function selectedMode() {
		if ($('#impersonateAllGroupAdmins').prop('checked')) {
			return 'all_groupadmins';
		}
		if ($('#impersonateIncludeGroups').prop('checked')) {
			return 'include_groups';
		}
		return 'admins';
	}

	function samePolicy(stored, sent) {
		return stored.mode === sent.mode
			&& stored.allowGroupAdminTargets === sent.allowGroupAdminTargets
			&& _.isArray(stored.groups)
			&& _.isEqual(_.clone(stored.groups).sort(), _.clone(sent.groups).sort());
	}

	/**
	 * The whole policy is stored by one request that the server validates, so the
	 * stored policy is never a mix of the old and the new one.
	 */
	function save() {
		if (reloading) {
			return;
		}
		if (pending) {
			// send the latest state once the running request is done
			dirty = true;
			return;
		}
		pending = true;
		dirty = false;
		var mode = selectedMode();
		var policy = {
			mode: mode,
			groups: mode === 'include_groups' ? groups : [],
			allowGroupAdminTargets: $groupAdminTargets.prop('checked') === true
		};
		$radios.prop('disabled', true);
		$groupAdminTargets.prop('disabled', true);
		$.ajax({
			url: OC.generateUrl('apps/impersonate/policy'),
			type: 'PUT',
			contentType: 'application/json',
			data: JSON.stringify(policy)
		}).done(function (response) {
			var stored = response && response.policy;
			if (!stored || !samePolicy(stored, policy)) {
				// the server stored something else (e.g. without a group that does not exist): show it
				reload();
			}
		}).fail(function () {
			reloading = true;
			dirty = false;
			OC.Notification.showTemporary(
				t('impersonate', 'The impersonation settings could not be saved. The page will be reloaded to show the settings that are in effect.')
			);
			setTimeout(reload, 3000);
		}).always(function () {
			pending = false;
			if (reloading) {
				// the controls stay disabled until the page shows the stored policy
				return;
			}
			$radios.prop('disabled', false);
			$groupAdminTargets.prop('disabled', false);
			if (dirty) {
				save();
			}
		});
	}

	$radios.change(function () {
		$('#selectIncludedGroups').toggleClass('hidden', selectedMode() !== 'include_groups');
		save();
	});

	$groupAdminTargets.change(save);

	$groups.each(function (index, element) {
		OC.Settings.setupGroupsSelect($(element));
		$(element).change(function (ev) {
			if (ev.added && String(ev.added.id).indexOf('|') !== -1) {
				// the group picker of ownCloud separates the ids with "|": it would hand over
				// other groups than the one that was picked, so nothing is stored
				reloading = true;
				OC.Notification.showTemporary(
					t('impersonate', 'A group whose id contains "|" can not be selected here. The page will be reloaded.')
				);
				setTimeout(reload, 3000);
				return;
			}
			groups = lockedGroups.concat(_.isArray(ev.val) ? _.map(ev.val, String) : []);
			save();
		});
	});
});
