from propelauth_py.errors import UnauthorizedException


class User:
    def __init__(self, user_id, org_id_to_org_member_info, email, first_name=None, last_name=None, username=None,
                 legacy_user_id=None, impersonator_user_id=None, metadata=None):
        self.user_id = user_id
        self.org_id_to_org_member_info = org_id_to_org_member_info
        self.email = email
        self.first_name = first_name
        self.last_name = last_name
        self.username = username
        self.legacy_user_id = legacy_user_id
        self.impersonator_user_id = impersonator_user_id
        self.metadata = metadata

    def __eq__(self, other):
        if isinstance(other, User):
            return self.user_id == other.user_id and self.org_id_to_org_member_info == other.org_id_to_org_member_info \
                and self.legacy_user_id == other.legacy_user_id and self.impersonator_user_id == other.impersonator_user_id \
                and self.email == other.email and self.first_name == other.first_name and self.last_name == other.last_name \
                and self.username == other.username and self.metadata == other.metadata

        return False

    def is_impersonated(self):
        """returns true if the user is impersonated"""
        return self.impersonator_user_id is not None


class OrgMemberInfo:
    def __init__(self, org_id, org_name, org_metadata, user_assigned_role, user_inherited_roles_plus_current_role,
                 user_permissions):
        self.org_id = org_id
        self.org_name = org_name
        self.org_metadata = org_metadata
        self.user_assigned_role = user_assigned_role
        self.user_inherited_roles_plus_current_role = user_inherited_roles_plus_current_role
        self.user_permissions = user_permissions

    def __eq__(self, other):
        if isinstance(other, OrgMemberInfo):
            return self.org_id == other.org_id and \
                self.org_name == other.org_name and \
                self.user_assigned_role == other.user_assigned_role
        return False

    def user_is_role(self, role):
        """returns true if the user is the role"""
        return role == self.user_assigned_role

    def user_is_at_least_role(self, role):
        """returns true if the user can act as the role"""
        return role in self.user_inherited_roles_plus_current_role

    def user_has_permission(self, permission):
        """returns true if user has the permission"""
        return permission in self.user_permissions

    def user_has_all_permissions(self, permissions):
        """returns true if user has the all the permissions listed"""
        for permission in permissions:
            if not self.user_has_permission(permission):
                return False

        return True


class UserAndOrgMemberInfo:
    def __init__(self, user, org_member_info):
        self.user = user
        self.org_member_info = org_member_info


def _to_org_member_info(org_id_to_org_member_info_json):
    if org_id_to_org_member_info_json is None:
        return None

    org_id_to_org_member_info = {}
    for org_id, org_member_info_json in org_id_to_org_member_info_json.items():
        user_assigned_role = org_member_info_json["user_role"]
        if user_assigned_role is not None:
            org_id_to_org_member_info[org_id] = OrgMemberInfo(
                org_id=org_member_info_json["org_id"],
                org_name=org_member_info_json["org_name"],
                org_metadata=org_member_info_json["org_metadata"],
                user_assigned_role=user_assigned_role,
                user_inherited_roles_plus_current_role=org_member_info_json["inherited_user_roles_plus_current_role"],
                user_permissions=org_member_info_json["user_permissions"],
            )
    return org_id_to_org_member_info


def _to_user(decoded_token):
    user_id = decoded_token.get("user_id")
    if user_id is None:
        raise UnauthorizedException.invalid_payload_in_access_token()

    org_id_to_org_member_info = _to_org_member_info(decoded_token.get("org_id_to_org_member_info"))
    return User(user_id, org_id_to_org_member_info, decoded_token.get("email"),
                first_name=decoded_token.get("first_name"),
                last_name=decoded_token.get("last_name"),
                username=decoded_token.get("username"),
                legacy_user_id=decoded_token.get("legacy_user_id"),
                impersonator_user_id=decoded_token.get("impersonator_user_id"),
                metadata=decoded_token.get("metadata"))
