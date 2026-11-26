/**
 * Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
 * Modified on 2026-11-26 by Marek Królikowski (TaKeN), see CHANGELOG.md.
 * Based on the ownCloud "impersonate" app, Copyright (C) 2015-2023 ownCloud GmbH and contributors.
 * SPDX-License-Identifier: AGPL-3.0-only - see LICENSE and COPYRIGHT.
 */
$(document).ready(function () {

	var context = {
		docUrl: OC.generateUrl('apps/files'),
		// Handlebars escapes {{displayText}} itself, so do not let t() escape the uid as well
		displayText: t('impersonate', 'Logged in as {currentUser}', {currentUser: OC.getCurrentUser().uid}, undefined, {escape: false})
	};

	var $html = OCA.Impersonate['impersonateNotification'](context);
	$($html).insertBefore("#notification");

});
