/**
 * Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
 * Modified on 2026-11-26 by Marek Królikowski (TaKeN), see CHANGELOG.md.
 * Based on the ownCloud "impersonate" app, Copyright (C) 2015-2023 ownCloud GmbH and contributors.
 * SPDX-License-Identifier: AGPL-3.0-only - see LICENSE and COPYRIGHT.
 */
(function(){
	function getDataForApp() {
		return $.get(
			OC.generateUrl('apps/impersonate/getimpersonatedata')
		).promise();
	}

	var promiseGetData = getDataForApp();

	function addImpersonateIcon ($localtr) {
		var context = {
			impersonate_src: OC.imagePath('core', 'actions/user.svg'),
			displayText: t('impersonate', 'Impersonate')
		};

		var $html = OCA.Impersonate['addImpersonateIcon'](context);
		$($html).insertAfter($localtr.find('.name'));
	}

	function removeImpersonateIcon ($localtr) {
		var context = {};
		var $html = OCA.Impersonate['removeImpersonateIcon'](context);
		$($html).insertAfter($localtr.find('.name'));
	}

	function parseFlag(value) {
		if (typeof value === 'boolean') {
			return value;
		}
		try {
			return JSON.parse($.trim(String(value))) === true;
		} catch (e) {
			return false;
		}
	}

	function parseGroups(value) {
		try {
			var groups = JSON.parse(value);
			return _.isArray(groups) ? _.map(groups, function(g) { return $.trim(String(g)); }) : [];
		} catch (e) {
			return [];
		}
	}

	/**
	 * Mirrors the server side rules (OCA\Impersonate\Policy); the server
	 * still checks every request.
	 */
	function canImpersonate(user, groupsOfUser, data) {
		if (!user || user.name === currentUser) {
			return false;
		}
		if (user.isEnabled === false || user.lastLogin === 0) {
			return false;
		}
		if (data.isAdmin) {
			return true;
		}
		// group admins can not impersonate administrators (the server only sends
		// the admins that are members of the group admin's groups)
		if (!data.isGroupAdmin || _.contains(data.adminUids, user.name)) {
			return false;
		}
		// the server only sends the groups this group admin may impersonate in
		return _.intersection(data.includedGroups, groupsOfUser).length > 0;
	}

	var currentUser = OC.getCurrentUser().uid;

	OC.Plugins.register('OC.Settings.UserList', {
		attach: function (obj) {
			var $newColumn = $("#userlist").find("tr:first-child");
			$('<th id="impersonateId" scope="col"></th>')
				.text(t('impersonate', 'Impersonate'))
				.insertAfter($newColumn.find("#headerName"));
			//Obj is UserList
			var oldAdd = obj.add;
			obj.add = function (user) {
				var $tr = oldAdd.apply(this, arguments);
				if (!$tr) {
					return $tr;
				}
				promiseGetData.then(function (result) {
					var data = {
						includedGroups: parseGroups(result[0]),
						includeGroupsMode: parseFlag(result[1]),
						allGroupAdminsMode: parseFlag(result[2]),
						isAdmin: parseFlag(result[3]),
						isGroupAdmin: parseFlag(result[4]),
						adminUids: parseGroups(result[5] || '[]')
					};

					//Clean up of impersonation
					$tr.find('.impersonate').parent().remove();
					$tr.find('.impersonateDisabled').remove();

					var groupsOfUser = $tr.find('.groups').data('groups');
					if (!_.isArray(groupsOfUser)) {
						// We need the gid.
						// For older OC versions (10.13-), the "groupsOfUser"
						// is an array containing groups. For newer OC versions (10.13+)
						// it maps each gid with additional data such as displayname, so
						// we need to extract the keys of the map
						groupsOfUser = _.keys(groupsOfUser || {});
					}

					if (canImpersonate(user, groupsOfUser, data)) {
						addImpersonateIcon($tr);
					} else {
						removeImpersonateIcon($tr);
					}
				});
				return $tr;
			};
		}
	});

	$(document).ready(function () {
		var pending = false;

		function impersonate(target) {
			// the session id changes when the impersonation starts: never send twice
			if (pending) {
				return;
			}
			pending = true;
			$.post(
				OC.generateUrl('apps/impersonate/user'),
				{ target: target }
			).done(function() {
				OC.redirect(OC.generateUrl(''));
			}).fail(function(xhr) {
				pending = false;
				var response = (xhr && xhr.responseJSON) || {};
				var message = response.message || t('impersonate', 'Can not impersonate');
				OC.dialogs.alert(message, t('impersonate', 'Error'));
			});
		}

		$('#userlist').on('click', '.impersonate', function(event) {
			event.preventDefault();
			var $tr = $(this).closest('tr');
			var target = $tr.data('uid') || $.trim($tr.find('.name').text());
			if (target) {
				impersonate(target);
			}
		});

	});

})();
