/**
 * Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
 * Modified on 2026-11-26 by Marek Królikowski (TaKeN), see CHANGELOG.md.
 * Based on the ownCloud "impersonate" app, Copyright (C) 2015-2023 ownCloud GmbH and contributors.
 * SPDX-License-Identifier: AGPL-3.0-only - see LICENSE and COPYRIGHT.
 */
$(document).ready(function () {
	$("#impersonateNoGroupAdmins").change(function () {
		$("#selectIncludedGroups").addClass('hidden');
		OC.AppConfig.setValue('impersonate', 'impersonate_all_groupadmins', 'false');
		OC.AppConfig.setValue('impersonate', 'impersonate_include_groups', 'false');
		OC.AppConfig.setValue('impersonate', 'impersonate_include_groups_list', JSON.stringify([]));
	});

	$("#impersonateIncludeGroups").change(function () {
		$("#selectIncludedGroups").removeClass('hidden');
		OC.AppConfig.setValue('impersonate', 'impersonate_include_groups', 'true');
		OC.AppConfig.setValue('impersonate', 'impersonate_all_groupadmins', 'false');
	});

	$("#impersonateAllGroupAdmins").change(function () {
		$("#selectIncludedGroups").addClass('hidden');
		OC.AppConfig.setValue('impersonate', 'impersonate_all_groupadmins', 'true');
		OC.AppConfig.setValue('impersonate', 'impersonate_include_groups', 'false');
		OC.AppConfig.setValue('impersonate', 'impersonate_include_groups_list', JSON.stringify([]));
	});

	$('#includedGroups').each(function (index, element) {
		OC.Settings.setupGroupsSelect($(element));
		$(element).change(function(ev) {
			var groups = ev.val || [];
			groups = JSON.stringify(groups);
			OC.AppConfig.setValue('impersonate', $(this).attr('name'), groups);
		});
	});
});

