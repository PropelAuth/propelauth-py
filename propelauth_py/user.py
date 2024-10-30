from typing import Optional, Any, Dict, Union
from propelauth_py.errors import UnauthorizedException
from propelauth_py.types.login_method import (
    to_login_method,
    PasswordLoginMethod,
    MagicLinkLoginMethod,
    SocialSsoLoginMethod,
    EmailConfirmationLinkLoginMethod,
    SamlSsoLoginMethod,
    ImpersonationLoginMethod,
    GeneratedFromBackendApiLoginMethod,
    UnknownLoginMethod
)

MULTI_ROLE = "multi_role"
SINGLE_ROLE = "single_role_in_hierarchy"

class OrgMemberInfo:
    def __init__(
        self,
        org_id: str,
        org_name: str,
        org_metadata: Dict[str, Any],
        user_assigned_role: str,
        url_safe_org_name: str,
        user_inherited_roles_plus_current_role: list[str],
        user_permissions: list[str],
        org_role_structure: str = SINGLE_ROLE,
        assigned_additional_roles: list[str] = [],
    ):
        self.org_id = org_id
        self.org_name = org_name
        self.org_metadata = org_metadata
        self.user_assigned_role = user_assigned_role
        self.user_inherited_roles_plus_current_role = (
            user_inherited_roles_plus_current_role
        )
        self.user_permissions = user_permissions
        self.org_role_structure = org_role_structure
        self.assigned_additional_roles = assigned_additional_roles
        self.url_safe_org_name = url_safe_org_name

    def __eq__(self, other):
        if isinstance(other, OrgMemberInfo):
            return (
                self.org_id == other.org_id
                and self.org_name == other.org_name
                and self.user_assigned_role == other.user_assigned_role
                and all([r in self.assigned_additional_roles for r in other.assigned_additional_roles])
            )
        return False
    def __getitem__(self, key):
        return getattr(self, key)
    def __repr__(self):
        return (
            f"OrgMemberInfo(org_id={self.org_id!r}, org_name={self.org_name!r}, "
            f"org_metadata={self.org_metadata!r}, user_assigned_role={self.user_assigned_role!r}, "
            f"url_safe_org_name={self.url_safe_org_name!r}, "
            f"user_inherited_roles_plus_current_role={self.user_inherited_roles_plus_current_role!r}, "
            f"user_permissions={self.user_permissions!r}, org_role_structure={self.org_role_structure!r}, "
            f"assigned_additional_roles={self.assigned_additional_roles!r})"
        )

    def user_is_role(self, role: str) -> bool:
        """returns true if the user is the role"""
        return (role == self.user_assigned_role or 
            (self.org_role_structure == MULTI_ROLE and role in self.assigned_additional_roles))

    def user_is_at_least_role(self, role: str) -> bool:
        """returns true if the user can act as the role"""
        if self.org_role_structure == MULTI_ROLE:
            return role == self.user_assigned_role or role in self.assigned_additional_roles
        else:
            return role in self.user_inherited_roles_plus_current_role

    def user_has_permission(self, permission: str) -> bool:
        """returns true if user has the permission"""
        return permission in self.user_permissions

    def user_has_all_permissions(self, permissions: list[str]) -> bool:
        """returns true if user has all the permissions listed"""
        for permission in permissions:
            if not self.user_has_permission(permission):
                return False

        return True

class User:
    def __init__(
        self,
        user_id: str,
        org_id_to_org_member_info,
        email: str,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        username: Optional[str] = None,
        properties: Optional[Dict[str, Any]] = None,
        legacy_user_id: Optional[str] = None,
        impersonator_user_id: Optional[str] = None,
        active_org_id: Optional[str] = None,
        login_method: Union[PasswordLoginMethod, MagicLinkLoginMethod, SocialSsoLoginMethod, EmailConfirmationLinkLoginMethod, SamlSsoLoginMethod, ImpersonationLoginMethod,GeneratedFromBackendApiLoginMethod,UnknownLoginMethod, None] = None,
    ):
        self.user_id = user_id
        self.org_id_to_org_member_info = org_id_to_org_member_info
        self.email = email
        self.first_name = first_name
        self.last_name = last_name
        self.username = username
        self.properties = properties
        self.legacy_user_id = legacy_user_id
        self.impersonator_user_id = impersonator_user_id
        self.active_org_id = active_org_id
        self.login_method = login_method

    def __eq__(self, other):
        if isinstance(other, User):
            return (
                self.user_id == other.user_id
                and self.org_id_to_org_member_info == other.org_id_to_org_member_info
                and self.legacy_user_id == other.legacy_user_id
                and self.impersonator_user_id == other.impersonator_user_id
                and self.email == other.email
                and self.first_name == other.first_name
                and self.last_name == other.last_name
                and self.username == other.username
                and self.properties == other.properties
                and self.active_org_id == other.active_org_id
                and self.login_method == other.login_method
            )

        return False
    def __getitem__(self, key):
        return getattr(self, key)
    def __repr__(self):
        return (
            f"User(user_id={self.user_id!r}, org_id_to_org_member_info={self.org_id_to_org_member_info!r}, "
            f"email={self.email!r}, first_name={self.first_name!r}, last_name={self.last_name!r}, "
            f"username={self.username!r}, properties={self.properties!r}, legacy_user_id={self.legacy_user_id!r}, "
            f"impersonator_user_id={self.impersonator_user_id!r}, active_org_id={self.active_org_id!r}, "
            f"login_method={self.login_method!r})"
        )

    def is_impersonated(self) -> bool:
        """Returns true if the user is impersonated"""
        return self.impersonator_user_id is not None

    def get_active_org(self) -> Optional[OrgMemberInfo]:
        """Returns the active org member info, if the user has an active org."""
        if self.active_org_id is None:
            return None
        return self.get_org(self.active_org_id)

    def get_active_org_id(self) -> Optional[str]:
        """Returns the active org id, if the user has an active org."""
        return self.active_org_id

    def get_org(self, org_id: str) -> Optional[OrgMemberInfo]:
        """Returns the org member info for the org_id, if the user is in the org."""
        return self.org_id_to_org_member_info.get(org_id)

    def get_org_by_name(self, org_name: str) -> Optional[OrgMemberInfo]:
        """Returns the org member info for the org_name, if the user is in the org."""
        for org_member_info in self.org_id_to_org_member_info.values():
            if org_member_info.org_name == org_name:
                return org_member_info
        return None

    def get_user_property(self, property_name: str):
        """Returns the user property value, if it exists."""
        return self.properties.get(property_name)

    def get_orgs(self) -> list[OrgMemberInfo]:
        """Returns the orgs the user is in."""
        return list(self.org_id_to_org_member_info.values())

    def is_role_in_org(self, org_id: str, role: str) -> bool:
        """Returns true if the user is the role in the org."""
        org_member_info = self.get_org(org_id)
        if not org_member_info:
            return False

        return org_member_info.user_is_role(role)

    def is_at_least_role_in_org(self, org_id: str, role: str) -> bool:
        """Returns true if the user is at least the role in the org."""
        org_member_info = self.get_org(org_id)
        if not org_member_info:
            return False

        return org_member_info.user_is_at_least_role(role)

    def has_permission_in_org(self, org_id: str, permission: str) -> bool:
        """Returns true if the user has the permission in the org."""
        org_member_info = self.get_org(org_id)
        if not org_member_info:
            return False

        return org_member_info.user_has_permission(permission)

    def has_all_permissions_in_org(self, org_id: str, permissions: list[str]) -> bool:
        """Returns true if the user has all the permissions in the org."""
        org_member_info = self.get_org(org_id)
        if not org_member_info:
            return False

        return org_member_info.user_has_all_permissions(permissions)


class UserAndOrgMemberInfo:
    def __init__(self, user: User, org_member_info: OrgMemberInfo):
        self.user = user
        self.org_member_info = org_member_info
    def __getitem__(self, key):
        return getattr(self, key)


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
                url_safe_org_name=org_member_info_json["url_safe_org_name"],
                user_inherited_roles_plus_current_role=org_member_info_json[
                    "inherited_user_roles_plus_current_role"
                ],
                user_permissions=org_member_info_json["user_permissions"],
                org_role_structure=org_member_info_json.get("org_role_structure", SINGLE_ROLE),
                assigned_additional_roles=org_member_info_json.get("additional_roles", []),
            )
    return org_id_to_org_member_info


def _to_user(decoded_token):
    user_id = decoded_token.get("user_id")
    if user_id is None:
        raise UnauthorizedException.invalid_payload_in_access_token()

    org_member_info = decoded_token.get("org_member_info")
    if org_member_info:
        active_org_id = org_member_info.get("org_id")
        org_id_to_org_member_info = _to_org_member_info(
            {active_org_id: org_member_info}
        )
    else:
        active_org_id = None
        org_id_to_org_member_info = _to_org_member_info(
            decoded_token.get("org_id_to_org_member_info")
        )

    return User(
        user_id,
        org_id_to_org_member_info,
        decoded_token.get("email"),
        first_name=decoded_token.get("first_name"),
        last_name=decoded_token.get("last_name"),
        username=decoded_token.get("username"),
        legacy_user_id=decoded_token.get("legacy_user_id"),
        impersonator_user_id=decoded_token.get("impersonator_user_id"),
        properties=decoded_token.get("properties"),
        active_org_id=active_org_id,
        login_method=to_login_method(decoded_token.get("login_method", {})),
    )