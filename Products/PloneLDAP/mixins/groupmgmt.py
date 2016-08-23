from Globals import InitializeClass
from AccessControl import ClassSecurityInfo


class GroupManagementMixin:
    """Implement Products.PlonePAS.interfaces.group.IGroupManagement
    """
    security = ClassSecurityInfo()

    security.declarePrivate('addGroup')
    def addGroup(self, group_id, **kwargs):
        self.acl_users.manage_addGroup(group_id)
        self.updateGroup(group_id=group_id, **kwargs)

    security.declarePrivate('addPrincipalToGroup')
    def addPrincipalToGroup(self, principal_id, group_id):
        plugins = self._getPAS()._getOb('plugins')

        group_id = self._verifyGroup(plugins, group_id=group_id)
        user = self.acl_users.getUserById(principal_id)

        if group_id and user:
            userDN = user.getUserDN()
            current_groups = self.acl_users.getGroups(dn=userDN, attr='dn')
            all_groups = self.acl_users.getGroups()
            newGroupDN = None
            x = 0
            while not newGroupDN and x < len(all_groups):
                group_cn, group_dn = all_groups[x]
                if group_cn == group_id:
                    newGroupDN = group_dn
                x += 1
            if newGroupDN:
                current_groups.append(newGroupDN)

            self.acl_users.manage_editUserRoles(userDN, current_groups)

            view_name = self.getId() + '_getGroupsForPrincipal'
            self.ZCacheable_invalidate(view_name = view_name)
            return True
        else:
            return False

    security.declarePrivate('updateGroup')
    def updateGroup(self, group_id, title=None, description=None, **kwargs):
        """ Update properties for 'group_id' """

        not_supported = [
            arg_name
            for arg_name, value in kwargs.iteritems()
            if value is not None
        ]

        if not_supported:
            raise NotImplementedError(
                'Handling of {} is not implemented'.format(not_supported)
            )

        old_attrs = self.acl_users.searchGroups(
            exact_match=True,
            cn=group_id,
        )[0]

        new_attrs = {}

        if title is not None:
            new_attrs['displayName'] = [title]
        if description is not None:
            new_attrs['description'] = [description]

        if new_attrs:
            self.acl_users.manage_update_group(
                dn=old_attrs['dn'],
                attrs=new_attrs,
            )

    security.declarePrivate('setRolesForGroup')
    def setRolesForGroup(self, group_id, roles=()):
        raise NotImplementedError()

    security.declarePrivate('removeGroup')
    def removeGroup(self, group_id):
        groups = self.enumerateGroups(id=group_id, exact_match=True)
        if groups:
            self.acl_users.manage_deleteGroups([info["dn"] for info in groups])

    security.declarePrivate('removePrincipalFromGroup')
    def removePrincipalFromGroup(self, principal_id, group_id):
        plugins = self._getPAS()._getOb('plugins')

        group_id = self._verifyGroup(plugins, group_id=group_id)
        user = self.acl_users.getUserById(principal_id)

        if group_id and user:
            userDN = user.getUserDN()
            current_groups = self.acl_users.getGroups(dn=userDN, attr='dn')
            all_groups = dict(self.acl_users.getGroups())
            group_dn = all_groups[group_id]

            new_groups = [g for g in current_groups if g!=group_dn]

            if len(new_groups) != len(current_groups):
                self.acl_users.manage_editUserRoles(userDN, new_groups)

            view_name = self.getId() + '_getGroupsForPrincipal'
            self.ZCacheable_invalidate(view_name = view_name)

            return True

        return False

InitializeClass(GroupManagementMixin)
