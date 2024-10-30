from typing import Any, Dict, Optional
from propelauth_py.user import OrgMemberInfo

OrgIdToOrgMemberInfo = Dict[str, OrgMemberInfo]

class Org:
    def __init__(
        self,
        org_id: str,
        name: str,
        max_users: Optional[int],
        is_saml_configured: bool,
        legacy_org_id: Optional[str],
        metadata: Dict[str, Any],
        custom_role_mapping_name: Optional[str],
    ):
        self.org_id = org_id
        self.name = name
        self.max_users = max_users
        self.is_saml_configured = is_saml_configured
        self.legacy_org_id = legacy_org_id
        self.metadata = metadata
        self.custom_role_mapping_name = custom_role_mapping_name

    def __repr__(self):
        return (
            f"Org(org_id={self.org_id!r}, name={self.name!r}, max_users={self.max_users}, "
            f"is_saml_configured={self.is_saml_configured}, legacy_org_id={self.legacy_org_id!r}, "
            f"metadata={self.metadata!r}, custom_role_mapping_name={self.custom_role_mapping_name!r})"
        )
    def __eq__(self, other):
        return isinstance(other, Org)
    def __getitem__(self, key):
        return getattr(self, key)
    
class Organization:
    def __init__(
        self,
        org_id: str,
        name: str,
        url_safe_org_slug: str,
        can_setup_saml: bool,
        is_saml_configured: bool,
        is_saml_in_test_mode: bool,
        max_users: Optional[int],
        metadata: Optional[Dict[str, Any]],
        domain: Optional[str],
        domain_autojoin: bool,
        domain_restrict: bool,
        custom_role_mapping_name: Optional[str],
        legacy_org_id: Optional[str],
    ):
        self.org_id = org_id
        self.name = name
        self.url_safe_org_slug = url_safe_org_slug
        self.can_setup_saml = can_setup_saml
        self.is_saml_configured = is_saml_configured
        self.is_saml_in_test_mode = is_saml_in_test_mode
        self.max_users = max_users
        self.metadata = metadata
        self.domain = domain
        self.domain_autojoin = domain_autojoin
        self.domain_restrict = domain_restrict
        self.custom_role_mapping_name = custom_role_mapping_name
        self.legacy_org_id = legacy_org_id

    def __repr__(self):
        return (
            f"Organization(org_id={self.org_id!r}, name={self.name!r}, url_safe_org_slug={self.url_safe_org_slug!r}, "
            f"can_setup_saml={self.can_setup_saml}, is_saml_configured={self.is_saml_configured}, "
            f"is_saml_in_test_mode={self.is_saml_in_test_mode}, max_users={self.max_users!r}, "
            f"metadata={self.metadata!r}, domain={self.domain!r}, domain_autojoin={self.domain_autojoin}, "
            f"domain_restrict={self.domain_restrict}, custom_role_mapping_name={self.custom_role_mapping_name!r}, "
            f"legacy_org_id={self.legacy_org_id!r})"
        )
    def __eq__(self, other):
        return isinstance(other, Organization)
    def __getitem__(self, key):
        return getattr(self, key)
    
    
class OrgQueryResponse:
    def __init__(
        self,
        orgs: list[Org],
        total_orgs: int,
        current_page: int,
        page_size: int,
        has_more_results: bool
    ):
        self.orgs = orgs
        self.total_orgs = total_orgs
        self.current_page = current_page
        self.page_size = page_size
        self.has_more_results = has_more_results

    def __repr__(self):
        return (
            f"OrgQueryResponse(orgs={self.orgs!r}, total_orgs={self.total_orgs}, "
            f"current_page={self.current_page}, page_size={self.page_size}, "
            f"has_more_results={self.has_more_results})"
        )
    def __eq__(self, other):
        return isinstance(other, OrgQueryResponse)
    def __getitem__(self, key):
        return getattr(self, key)

class PendingInvite:
    def __init__(
        self,
        invitee_email: str,
        org_id: str,
        org_name: str,
        role_in_org: str,
        additional_roles_in_org: list[str],
        created_at: int,
        expires_at: int,
        inviter_email: Optional[str],
        inviter_user_id: Optional[str]
    ):
        self.invitee_email = invitee_email
        self.org_id = org_id
        self.org_name = org_name
        self.role_in_org = role_in_org
        self.additional_roles_in_org = additional_roles_in_org
        self.created_at = created_at
        self.expires_at = expires_at
        self.inviter_email = inviter_email
        self.inviter_user_id = inviter_user_id

    def __repr__(self):
        return (
            f"PendingInvite(invitee_email={self.invitee_email!r}, org_id={self.org_id!r}, "
            f"org_name={self.org_name!r}, role_in_org={self.role_in_org!r}, "
            f"additional_roles_in_org={self.additional_roles_in_org!r}, created_at={self.created_at}, "
            f"expires_at={self.expires_at}, inviter_email={self.inviter_email!r}, "
            f"inviter_user_id={self.inviter_user_id!r})"
        )
    def __eq__(self, other):
        return isinstance(other, PendingInvite)
    def __getitem__(self, key):
        return getattr(self, key)
        
        
class PendingInvitesPage:
    def __init__(
        self,
        total_invites: int,
        current_page: int,
        page_size: int,
        has_more_results: bool,
        invites: list[PendingInvite]
    ):
        self.total_invites = total_invites
        self.current_page = current_page
        self.page_size = page_size
        self.has_more_results = has_more_results
        self.invites = invites

    def __repr__(self):
        return (
            f"PendingInvitesPage(total_invites={self.total_invites}, current_page={self.current_page}, "
            f"page_size={self.page_size}, has_more_results={self.has_more_results}, "
            f"invites={self.invites!r})"
        )
    def __eq__(self, other):
        return isinstance(other, PendingInvitesPage)
    def __getitem__(self, key):
        return getattr(self, key)
    
    
class CreatedOrg:
    def __init__(
        self,
        org_id: str,
        name: str
    ):
        self.org_id = org_id
        self.name = name

    def __repr__(self):
        return (
            f"CreatedOrg(org_id={self.org_id!r}, name={self.name!r})"
        )
    def __eq__(self, other):
        return isinstance(other, CreatedOrg)
    def __getitem__(self, key):
        return getattr(self, key)

class UserMetadata:
    def __init__(
        self,
        user_id: str,
        email: str,
        email_confirmed: bool,
        has_password: bool,
        username: Optional[str],
        first_name: Optional[str],
        last_name: Optional[str],
        picture_url: Optional[str],
        locked: bool,
        enabled: bool,
        mfa_enabled: bool,
        can_create_orgs: bool,
        created_at: int,
        last_active_at: int,
        org_id_to_org_info: Optional[OrgIdToOrgMemberInfo],
        legacy_org_id: Optional[str],
        impersonator_user_id: Optional[str],
        metadata: Optional[Dict[str, Any]],
        properties: Optional[Dict[str, Any]]
    ):
        self.user_id = user_id
        self.email = email
        self.email_confirmed = email_confirmed
        self.has_password = has_password
        self.username = username
        self.first_name = first_name
        self.last_name = last_name
        self.picture_url = picture_url
        self.locked = locked
        self.enabled = enabled
        self.mfa_enabled = mfa_enabled
        self.can_create_orgs = can_create_orgs
        self.created_at = created_at
        self.last_active_at = last_active_at
        self.org_id_to_org_info = org_id_to_org_info
        self.legacy_org_id = legacy_org_id
        self.impersonator_user_id = impersonator_user_id
        self.metadata = metadata
        self.properties = properties

    def __repr__(self): 
        return (
            f"UserMetadata(user_id={self.user_id!r}, email={self.email!r}, "
            f"email_confirmed={self.email_confirmed}, has_password={self.has_password}, "
            f"username={self.username!r}, first_name={self.first_name!r}, last_name={self.last_name!r}, "
            f"picture_url={self.picture_url!r}, locked={self.locked}, enabled={self.enabled}, "
            f"mfa_enabled={self.mfa_enabled}, can_create_orgs={self.can_create_orgs}, "
            f"created_at={self.created_at}, last_active_at={self.last_active_at}, "
            f"org_id_to_org_info={self.org_id_to_org_info!r}, legacy_org_id={self.legacy_org_id!r}, "
            f"impersonator_user_id={self.impersonator_user_id!r}, metadata={self.metadata!r}, "
            f"properties={self.properties!r})"
        )
    def __eq__(self, other):
        return isinstance(other, UserMetadata)
    def __getitem__(self, key):
        return getattr(self, key)
    
class OrgApiKeyValidation:
    def __init__(
        self,
        metadata: Optional[Dict[str, Any]],
        org: Org,
        user: Optional[UserMetadata],
        user_in_org: Optional[OrgMemberInfo]
    ):
        self.metadata = metadata
        self.org = org
        self.user = user
        self.user_in_org = user_in_org

    def __repr__(self):
        return (
            f"OrgApiKeyValidation(metadata={self.metadata!r}, org={self.org!r}, "
            f"user={self.user!r}, user_in_org={self.user_in_org!r})"
        )
    def __eq__(self, other):
        return isinstance(other, OrgApiKeyValidation)
    def __getitem__(self, key):
        return getattr(self, key)
    
class CreatedUser:
    def __init__(
        self,
        user_id: str,
    ):
        self.user_id = user_id
        
    def __repr__(self):
        return (
            f"CreatedUser(user_id={self.user_id!r})"
        )
    def __eq__(self, other):
        return isinstance(other, CreatedUser)
    def __getitem__(self, key):
        return getattr(self, key)
    
    
class UsersPagedResponse:
    def __init__(
        self,
        users: list[UserMetadata],
        total_users: int,
        current_page: int,
        page_size: int,
        has_more_results: bool
    ):
        self.users = users
        self.total_users = total_users
        self.current_page = current_page
        self.page_size = page_size
        self.has_more_results = has_more_results

    def __repr__(self):
        return (
            f"UsersPagedResponse(users={self.users!r}, total_users={self.total_users}, "
            f"current_page={self.current_page}, page_size={self.page_size}, "
            f"has_more_results={self.has_more_results})"
        )
    def __eq__(self, other):
        return isinstance(other, UsersPagedResponse)
    def __getitem__(self, key):
        return getattr(self, key)
    
    
class PersonalApiKeyValidation:
    def __init__(
        self,
        metadata: Optional[Dict[str, Any]],
        user: UserMetadata
    ):
        self.metadata = metadata
        self.user = user

    def __repr__(self):
        return (
            f"PersonalApiKeyValidation(metadata={self.metadata!r}, user={self.user!r})"
        )
    def __eq__(self, other):
        return isinstance(other, PersonalApiKeyValidation)
    def __getitem__(self, key):
        return getattr(self, key)

class UserSignupQueryParams:
    def __init__(
        self,
        user_signup_query_parameters: Dict[str, str]
    ):
        self.user_signup_query_parameters = user_signup_query_parameters

    def __repr__(self):
        return (
            f"UserSignupQueryParams(user_signup_query_parameters={self.user_signup_query_parameters!r})"
        )
    def __eq__(self, other):
        return isinstance(other, UserSignupQueryParams)
    def __getitem__(self, key):
        return getattr(self, key)
