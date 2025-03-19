from typing import Any, Dict, Optional, List
from propelauth_py.user import OrgMemberInfo
from dataclasses import dataclass

OrgIdToOrgMemberInfo = Dict[str, OrgMemberInfo]


@dataclass
class Org:
    org_id: str
    name: str
    max_users: Optional[int]
    is_saml_configured: bool
    legacy_org_id: Optional[str]
    metadata: Dict[str, Any]
    custom_role_mapping_name: Optional[str]

    def __getitem__(self, key):
        return getattr(self, key)
    
@dataclass
class OrgFromApiKey:
    org_id: str
    name: str
    org_name: str
    max_users: Optional[int]
    is_saml_configured: bool
    legacy_org_id: Optional[str]
    metadata: Dict[str, Any]
    custom_role_mapping_name: Optional[str]

    def __getitem__(self, key):
        return getattr(self, key)


@dataclass
class Organization:
    org_id: str
    name: str
    url_safe_org_slug: str
    can_setup_saml: bool
    is_saml_configured: bool
    is_saml_in_test_mode: bool
    max_users: Optional[int]
    metadata: Optional[Dict[str, Any]]
    domain: Optional[str]
    extra_domains: List[str]
    domain_autojoin: bool
    domain_restrict: bool
    custom_role_mapping_name: Optional[str]
    legacy_org_id: Optional[str]

    def __getitem__(self, key):
        return getattr(self, key)


@dataclass
class OrgQueryResponse:
    orgs: List[Org]
    total_orgs: int
    current_page: int
    page_size: int
    has_more_results: bool

    def __getitem__(self, key):
        return getattr(self, key)


@dataclass
class PendingInvite:
    invitee_email: str
    org_id: str
    org_name: str
    role_in_org: str
    additional_roles_in_org: List[str]
    created_at: int
    expires_at: int
    inviter_email: Optional[str]
    inviter_user_id: Optional[str]

    def __getitem__(self, key):
        return getattr(self, key)


@dataclass
class PendingInvitesPage:
    total_invites: int
    current_page: int
    page_size: int
    has_more_results: bool
    invites: List[PendingInvite]

    def __getitem__(self, key):
        return getattr(self, key)


@dataclass
class CreatedOrg:
    org_id: str
    name: str

    def __getitem__(self, key):
        return getattr(self, key)


@dataclass
class UserMetadata:
    user_id: str
    email: str
    email_confirmed: bool
    has_password: bool
    username: Optional[str]
    first_name: Optional[str]
    last_name: Optional[str]
    picture_url: Optional[str]
    locked: bool
    enabled: bool
    mfa_enabled: bool
    can_create_orgs: bool
    created_at: int
    last_active_at: int
    org_id_to_org_info: Optional[OrgIdToOrgMemberInfo]
    legacy_user_id: Optional[str]
    impersonator_user_id: Optional[str]
    metadata: Optional[Dict[str, Any]]
    properties: Optional[Dict[str, Any]]

    def __getitem__(self, key):
        return getattr(self, key)


@dataclass
class OrgApiKeyValidation:
    metadata: Optional[Dict[str, Any]]
    org: OrgFromApiKey
    user: Optional[UserMetadata]
    user_in_org: Optional[OrgMemberInfo]

    def __getitem__(self, key):
        return getattr(self, key)


@dataclass
class CreatedUser:
    user_id: str

    def __getitem__(self, key):
        return getattr(self, key)


@dataclass
class UsersPagedResponse:
    users: List[UserMetadata]
    total_users: int
    current_page: int
    page_size: int
    has_more_results: bool

    def __getitem__(self, key):
        return getattr(self, key)


@dataclass
class PersonalApiKeyValidation:
    metadata: Optional[Dict[str, Any]]
    user: UserMetadata

    def __getitem__(self, key):
        return getattr(self, key)


@dataclass
class UserSignupQueryParams:
    user_signup_query_parameters: Dict[str, str]

    def __getitem__(self, key):
        return getattr(self, key)
