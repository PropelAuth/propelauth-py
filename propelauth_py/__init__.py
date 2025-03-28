from typing import Optional, Any, Dict, List
from propelauth_py.user import UserAndOrgMemberInfo, User
from propelauth_py.jwt import _validate_access_token_and_get_user
from propelauth_py.api import token_verification_metadata, TokenVerificationMetadata, OrgQueryOrderBy, UserQueryOrderBy
from propelauth_py.api.user import (
    _clear_user_password,
    _fetch_user_metadata_by_user_id,
    _fetch_user_metadata_by_email,
    _fetch_user_metadata_by_username,
    _fetch_batch_user_metadata_by_user_ids,
    _fetch_batch_user_metadata_by_emails,
    _fetch_batch_user_metadata_by_usernames,
    _fetch_user_signup_query_params_by_user_id,
    _fetch_users_by_query,
    _fetch_users_in_org,
    _create_user,
    _logout_all_user_sessions,
    _update_user_email,
    _update_user_metadata,
    _delete_user,
    _disable_user,
    _enable_user,
    _update_user_password,
    _disable_user_2fa,
    _enable_user_can_create_orgs,
    _disable_user_can_create_orgs,
    _validate_personal_api_key,
    _invite_user_to_org,
    _resend_email_confirmation,

)
from propelauth_py.api.access_token import _create_access_token
from propelauth_py.api.end_user_api_keys import (
    _create_api_key,
    _delete_api_key,
    _fetch_api_key,
    _fetch_archived_api_keys,
    _fetch_current_api_keys,
    _update_api_key,
    _validate_api_key,
)
from propelauth_py.api.magic_link import _create_magic_link
from propelauth_py.api.migrate_user import _migrate_user_from_external_source, _migrate_user_password
from propelauth_py.api.org import (
    _add_user_to_org,
    _allow_org_to_setup_saml_connection,
    _change_user_role_in_org,
    _create_org,
    _create_org_saml_connection_link,
    _delete_org,
    _disallow_org_to_setup_saml_connection,
    _fetch_custom_role_mappings,
    _fetch_org,
    _fetch_org_by_query,
    _fetch_pending_invites,
    _remove_user_from_org,
    _revoke_pending_org_invite,
    _subscribe_org_to_role_mapping,
    _update_org_metadata,
    _validate_org_api_key,
    _fetch_saml_sp_metadata,
    _set_saml_idp_metadata,
    _saml_go_live,
    _delete_saml_connection,
)
from propelauth_py.api.token_verification_metadata import (
    _fetch_token_verification_metadata,
)

from propelauth_py.auth_fns import (
    validate_all_permissions_and_get_org,
    validate_exact_org_role_and_get_org,
    validate_minimum_org_role_and_get_org,
    validate_org_access_and_get_org_member_info,
    validate_permission_and_get_org,
    _extract_token_from_authorization_header,
    wrap_validate_access_token_and_get_user,
    wrap_validate_access_token_and_get_user_with_org,
    wrap_validate_access_token_and_get_user_with_org_by_all_permissions,
    wrap_validate_access_token_and_get_user_with_org_by_exact_role,
    wrap_validate_access_token_and_get_user_with_org_by_minimum_role,
    wrap_validate_access_token_and_get_user_with_org_by_permission,
)
from propelauth_py.errors import (
    ForbiddenException,
    UnauthorizedException,
    EndUserApiKeyRateLimitedException,
    EndUserApiKeyException,
    RateLimitedException,
)
from propelauth_py.types.login_method import (
    EmailConfirmationLinkLoginMethod,
    GeneratedFromBackendApiLoginMethod,
    ImpersonationLoginMethod,
    MagicLinkLoginMethod,
    PasswordLoginMethod,
    SamlLoginProvider,
    SamlSsoLoginMethod,
    SocialLoginProvider,
    SocialSsoLoginMethod,
    UnknownLoginMethod,
)
from propelauth_py.types.saml_types import SamlIdpMetadata

from propelauth_py.validation import _validate_and_extract_auth_hostname

class Auth:
    
    def __init__(self, auth_hostname: str, integration_api_key: str, token_verification_metadata: Optional[TokenVerificationMetadata]):
        self.auth_hostname = auth_hostname
        self.integration_api_key = integration_api_key
        self.token_verification_metadata = token_verification_metadata

    def fetch_user_metadata_by_user_id(self, user_id: str, include_orgs: bool = False):
        return _fetch_user_metadata_by_user_id(self.auth_hostname, self.integration_api_key, user_id, include_orgs)

    def fetch_user_metadata_by_email(self, email: str, include_orgs: bool = False):
        return _fetch_user_metadata_by_email(self.auth_hostname, self.integration_api_key, email, include_orgs)
    
    def fetch_user_metadata_by_username(self, username: str, include_orgs: bool = False):
        return _fetch_user_metadata_by_username(
            self.auth_hostname, self.integration_api_key, username, include_orgs
        )

    def fetch_user_signup_query_params_by_user_id(self, user_id: str):
        return _fetch_user_signup_query_params_by_user_id(
            self.auth_hostname, self.integration_api_key, user_id
        )

    def fetch_batch_user_metadata_by_user_ids(self, user_ids: List[str], include_orgs: bool = False):
        return _fetch_batch_user_metadata_by_user_ids(
            self.auth_hostname, self.integration_api_key, user_ids, include_orgs
        )

    def fetch_batch_user_metadata_by_emails(self, emails: List[str], include_orgs: bool = False):
        return _fetch_batch_user_metadata_by_emails(
            self.auth_hostname, self.integration_api_key, emails, include_orgs
        )

    def fetch_batch_user_metadata_by_usernames(self, usernames: List[str], include_orgs: bool = False):
        return _fetch_batch_user_metadata_by_usernames(
            self.auth_hostname, self.integration_api_key, usernames, include_orgs
        )

    def fetch_org(self, org_id: str):
        return _fetch_org(self.auth_hostname, self.integration_api_key, org_id)

    def fetch_org_by_query(
        self, page_size: int = 10, page_number: int = 0, order_by: OrgQueryOrderBy = OrgQueryOrderBy.CREATED_AT_ASC, name: Optional[str] = None, legacy_org_id: Optional[str] = None, domain: Optional[str] = None
    ):
        return _fetch_org_by_query(
            self.auth_hostname,
            self.integration_api_key,
            page_size,
            page_number,
            order_by,
            name,
            legacy_org_id,
            domain,
        )

    def fetch_custom_role_mappings(self):
        return _fetch_custom_role_mappings(
            self.auth_hostname,
            self.integration_api_key,
        )

    def fetch_pending_invites(self, page_number: int = 0, page_size: int = 10, org_id: Optional[str] = None):
        return _fetch_pending_invites(
            self.auth_hostname,
            self.integration_api_key,
            page_number,
            page_size,
            org_id,
        )

    def fetch_users_by_query(
        self,
        page_size: int = 10,
        page_number: int = 0,
        order_by: UserQueryOrderBy = UserQueryOrderBy.CREATED_AT_ASC,
        email_or_username: Optional[str] = None,
        include_orgs: bool = False,
        legacy_user_id: Optional[str] = None
    ):
        return _fetch_users_by_query(
            self.auth_hostname,
            self.integration_api_key,
            page_size,
            page_number,
            order_by,
            email_or_username,
            include_orgs,
            legacy_user_id
        )

    def fetch_users_in_org(
        self, org_id: str, page_size: int = 10, page_number: int = 0, include_orgs: bool = False, role: Optional[str] = None
    ):
        return _fetch_users_in_org(
            self.auth_hostname,
            self.integration_api_key,
            org_id,
            page_size,
            page_number,
            include_orgs,
            role,
        )

    def create_user(
        self,
        email: str,
        email_confirmed: bool = False,
        send_email_to_confirm_email_address: bool = True,
        ask_user_to_update_password_on_login: bool = False,
        password: Optional[str] = None,
        username: Optional[str] = None,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        properties: Optional[Dict[str, Any]] = None,
        ignore_domain_restrictions: bool = False
    ):
        return _create_user(
            self.auth_hostname,
            self.integration_api_key,
            email,
            email_confirmed,
            send_email_to_confirm_email_address,
            ask_user_to_update_password_on_login,
            password,
            username,
            first_name,
            last_name,
            properties,
            ignore_domain_restrictions
        )

    def invite_user_to_org(self, email: str, org_id: str, role: str, additional_roles: List[str] = []):
        return _invite_user_to_org(
            self.auth_hostname,
            self.integration_api_key,
            email,
            org_id,
            role,
            additional_roles,
        )

    def resend_email_confirmation(self, user_id: str):
        return _resend_email_confirmation(
            self.auth_hostname,
            self.integration_api_key,
            user_id,
        )

    def logout_all_user_sessions(self, user_id: str):
        return _logout_all_user_sessions(
            self.auth_hostname,
            self.integration_api_key,
            user_id,
        )

    def update_user_email(self, user_id: str, new_email: str, require_email_confirmation: bool):
        return _update_user_email(
            self.auth_hostname,
            self.integration_api_key,
            user_id,
            new_email,
            require_email_confirmation,
        )

    def update_user_metadata(
        self,
        user_id: str,
        username: Optional[str] = None,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        properties: Optional[Dict[str, Any]] = None,
        picture_url: Optional[str] = None,
        update_password_required: Optional[bool] = None,
        legacy_user_id: Optional[str] = None,
    ):
        return _update_user_metadata(
            self.auth_hostname,
            self.integration_api_key,
            user_id=user_id,
            username=username,
            first_name=first_name,
            last_name=last_name,
            metadata=metadata,
            properties=properties,
            picture_url=picture_url,
            update_password_required=update_password_required,
            legacy_user_id=legacy_user_id
        )

    def clear_user_password(self, user_id: str):
        return _clear_user_password(self.auth_hostname, self.integration_api_key, user_id)

    def update_user_password(
        self, user_id: str, password: str, ask_user_to_update_password_on_login: bool = False
    ):
        return _update_user_password(
            self.auth_hostname,
            self.integration_api_key,
            user_id,
            password,
            ask_user_to_update_password_on_login,
        )

    def create_magic_link(
        self, 
        email: str,
        redirect_to_url: Optional[str] = None,
        expires_in_hours: Optional[str] = None,
        create_new_user_if_one_doesnt_exist: Optional[bool] = None,
        user_signup_query_parameters: Optional[Dict[str, str]] = None,
    ):
        return _create_magic_link(
            self.auth_hostname,
            self.integration_api_key,
            email,
            redirect_to_url,
            expires_in_hours,
            create_new_user_if_one_doesnt_exist,
            user_signup_query_parameters,
        )

    def create_access_token(
        self, 
        user_id: str, 
        duration_in_minutes: int,
        active_org_id: Optional[str] = None
    ):
        return _create_access_token(
            self.auth_hostname, self.integration_api_key, user_id, duration_in_minutes, active_org_id
        )

    def migrate_user_from_external_source(
        self,
        email: str,
        email_confirmed: bool,
        existing_user_id: Optional[str] = None,
        existing_password_hash: Optional[str] = None,
        existing_mfa_base32_encoded_secret: Optional[str] = None,
        ask_user_to_update_password_on_login: bool = False,
        enabled: Optional[bool] = None,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        username: Optional[str] = None,
        picture_url: Optional[str] = None,
        properties: Optional[Dict[str, Any]] = None,
    ):
        return _migrate_user_from_external_source(
            self.auth_hostname,
            self.integration_api_key,
            email,
            email_confirmed,
            existing_user_id,
            existing_password_hash,
            existing_mfa_base32_encoded_secret,
            ask_user_to_update_password_on_login,
            enabled,
            first_name,
            last_name,
            username,
            picture_url,
            properties,
        )
        
    def migrate_user_password(
        self,
        user_id: str,
        password_hash: str,
    ):
        return _migrate_user_password(
            self.auth_hostname,
            self.integration_api_key,
            user_id,
            password_hash
        )

    def create_org(
        self,
        name: str,
        enable_auto_joining_by_domain: bool = False,
        members_must_have_matching_domain: bool = False,
        domain: Optional[str] = None,
        max_users: Optional[str] = None,
        custom_role_mapping_name: Optional[str] = None,
        legacy_org_id: Optional[str] = None,
    ):
        return _create_org(
            self.auth_hostname,
            self.integration_api_key,
            name,
            enable_auto_joining_by_domain,
            members_must_have_matching_domain,
            domain,
            max_users,
            custom_role_mapping_name,
            legacy_org_id,
        )

    def update_org_metadata(
        self,
        org_id: str,
        name: Optional[str] = None,
        can_setup_saml: Optional[bool] = None,
        metadata: Optional[Dict[str, Any]] = None,
        max_users: Optional[str] = None,
        can_join_on_email_domain_match: Optional[bool] = None,
        members_must_have_email_domain_match: Optional[bool] = None,
        domain: Optional[str] = None,
        require_2fa_by: Optional[str] = None,
        extra_domains: Optional[List[str]] = None,
    ):
        return _update_org_metadata(
            self.auth_hostname,
            self.integration_api_key,
            org_id=org_id,
            name=name,
            can_setup_saml=can_setup_saml,
            metadata=metadata,
            max_users=max_users,
            can_join_on_email_domain_match=can_join_on_email_domain_match,
            members_must_have_email_domain_match=members_must_have_email_domain_match,
            domain=domain,
            require_2fa_by=require_2fa_by,
            extra_domains=extra_domains
        )

    def subscribe_org_to_role_mapping(self, org_id: str, custom_role_mapping_name: str):
        return _subscribe_org_to_role_mapping(
            self.auth_hostname,
            self.integration_api_key,
            org_id,
            custom_role_mapping_name,
        )
        
    def fetch_saml_sp_metadata(self, org_id: str):
        return _fetch_saml_sp_metadata(
            self.auth_hostname,
            self.integration_api_key,
            org_id,
        )
        
    def set_saml_idp_metadata(self, org_id: str, saml_idp_metadata: SamlIdpMetadata):
        return _set_saml_idp_metadata(
            self.auth_hostname,
            self.integration_api_key,
            org_id,
            saml_idp_metadata,
        )
        
    def saml_go_live(self, org_id: str):
        return _saml_go_live(
            self.auth_hostname,
            self.integration_api_key,
            org_id,
        )
        
    def delete_saml_connection(self, org_id: str):
        return _delete_saml_connection(
            self.auth_hostname,
            self.integration_api_key,
            org_id,
        )

    def delete_org(self, org_id: str):
        return _delete_org(self.auth_hostname, self.integration_api_key, org_id)
    
    def revoke_pending_org_invite(self, org_id: str, invitee_email: str):
        return _revoke_pending_org_invite(self.auth_hostname, self.integration_api_key, org_id, invitee_email)


    def add_user_to_org(self, user_id: str, org_id: str, role: str, additional_roles: List[str] = []):
        return _add_user_to_org(
            self.auth_hostname, self.integration_api_key, user_id, org_id, role, additional_roles
        )

    def remove_user_from_org(self, user_id: str, org_id: str):
        return _remove_user_from_org(self.auth_hostname, self.integration_api_key, user_id, org_id)

    def change_user_role_in_org(self, user_id: str, org_id: str, role: str, additional_roles: List[str] = []):
        return _change_user_role_in_org(
            self.auth_hostname, self.integration_api_key, user_id, org_id, role, additional_roles
        )

    def delete_user(self, user_id: str):
        return _delete_user(self.auth_hostname, self.integration_api_key, user_id)

    def disable_user(self, user_id: str):
        return _disable_user(self.auth_hostname, self.integration_api_key, user_id)

    def enable_user(self, user_id: str):
        return _enable_user(self.auth_hostname, self.integration_api_key, user_id)

    def disable_user_2fa(self, user_id: str):
        return _disable_user_2fa(self.auth_hostname, self.integration_api_key, user_id)

    def enable_user_can_create_orgs(self, user_id: str):
        return _enable_user_can_create_orgs(self.auth_hostname, self.integration_api_key, user_id)

    def disable_user_can_create_orgs(self, user_id: str):
        return _disable_user_can_create_orgs(self.auth_hostname, self.integration_api_key, user_id)

    def allow_org_to_setup_saml_connection(self, org_id: str):
        return _allow_org_to_setup_saml_connection(
            self.auth_hostname, self.integration_api_key, org_id
        )

    def disallow_org_to_setup_saml_connection(self, org_id: str):
        return _disallow_org_to_setup_saml_connection(
            self.auth_hostname, self.integration_api_key, org_id
        )

    def create_org_saml_connection_link(self, org_id: str, expires_in_seconds=None):
        return _create_org_saml_connection_link(
            self.auth_hostname, self.integration_api_key, org_id, expires_in_seconds
        )

    # functions for end user api keys

    def fetch_api_key(self, api_key_id: str):
        return _fetch_api_key(self.auth_hostname, self.integration_api_key, api_key_id)

    def fetch_current_api_keys(
        self,
        org_id: Optional[str] = None,
        user_id: Optional[str] = None,
        user_email: Optional[str] = None,
        page_size: Optional[int] = None,
        page_number: Optional[int] = None,
        api_key_type: Optional[str] = None,
    ):
        return _fetch_current_api_keys(
            self.auth_hostname,
            self.integration_api_key,
            org_id,
            user_id,
            user_email,
            page_size,
            page_number,
            api_key_type,
        )

    def fetch_archived_api_keys(
        self,
        org_id: Optional[str] = None,
        user_id: Optional[str] = None,
        user_email: Optional[str] = None,
        page_size: Optional[int] = None,
        page_number: Optional[int] = None,
        api_key_type: Optional[str] = None,
    ):
        return _fetch_archived_api_keys(
            self.auth_hostname,
            self.integration_api_key,
            org_id,
            user_id,
            user_email,
            page_size,
            page_number,
            api_key_type=api_key_type,
        )

    def create_api_key(
        self, org_id: Optional[str] = None, user_id: Optional[str] = None, expires_at_seconds: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None
    ):
        return _create_api_key(
            self.auth_hostname, self.integration_api_key, org_id, user_id, expires_at_seconds, metadata
        )

    def update_api_key(self, api_key_id: str, expires_at_seconds: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None):
        return _update_api_key(
            self.auth_hostname, self.integration_api_key, api_key_id, expires_at_seconds, metadata
        )

    def delete_api_key(self, api_key_id: str):
        return _delete_api_key(self.auth_hostname, self.integration_api_key, api_key_id)

    def validate_personal_api_key(self, api_key_token: str):
        return _validate_personal_api_key(self.auth_hostname, self.integration_api_key, api_key_token)

    def validate_org_api_key(self, api_key_token: str):
        return _validate_org_api_key(self.auth_hostname, self.integration_api_key, api_key_token)

    def validate_api_key(self, api_key_token: str):
        return _validate_api_key(self.auth_hostname, self.integration_api_key, api_key_token)
    

    def validate_access_token_and_get_user(self, authorization_header: Optional[str]):
        access_token = _extract_token_from_authorization_header(authorization_header)
        user = _validate_access_token_and_get_user(access_token, self.token_verification_metadata)
        return user
    
    def validate_access_token_and_get_user_with_org(self, authorization_header: Optional[str], required_org_id: str):
        access_token = _extract_token_from_authorization_header(authorization_header)
        user = _validate_access_token_and_get_user(access_token, self.token_verification_metadata)
        org_member_info = validate_org_access_and_get_org_member_info(user, required_org_id)
        return UserAndOrgMemberInfo(user, org_member_info)
    
    def validate_access_token_and_get_user_with_org_by_minimum_role(self, authorization_header: Optional[str], required_org_id: str, minimum_required_role: str):
        access_token = _extract_token_from_authorization_header(authorization_header)
        user = _validate_access_token_and_get_user(access_token, self.token_verification_metadata)
        org_member_info = validate_minimum_org_role_and_get_org(user, required_org_id, minimum_required_role)
        return UserAndOrgMemberInfo(user, org_member_info)
    
    def validate_access_token_and_get_user_with_org_by_exact_role(self, authorization_header: Optional[str], required_org_id: str, required_role: str):
        access_token = _extract_token_from_authorization_header(authorization_header)
        user = _validate_access_token_and_get_user(access_token, self.token_verification_metadata)
        org_member_info = validate_exact_org_role_and_get_org(user, required_org_id, required_role)
        return UserAndOrgMemberInfo(user, org_member_info)
    
    def validate_access_token_and_get_user_with_org_by_permission(self, authorization_header: Optional[str], required_org_id: str, permission: str):
        access_token = _extract_token_from_authorization_header(authorization_header)
        user = _validate_access_token_and_get_user(access_token, self.token_verification_metadata)
        org_member_info = validate_permission_and_get_org(user, required_org_id, permission)
        return UserAndOrgMemberInfo(user, org_member_info)
    
    def validate_access_token_and_get_user_with_org_by_all_permissions(self, authorization_header: Optional[str], required_org_id: str, permissions: List[str]):
        access_token = _extract_token_from_authorization_header(authorization_header)
        user = _validate_access_token_and_get_user(access_token, self.token_verification_metadata)
        org_member_info = validate_all_permissions_and_get_org(user, required_org_id, permissions)
        return UserAndOrgMemberInfo(user, org_member_info)
    
    def validate_org_access_and_get_org(self, user: User, required_org_id: str):
        return validate_org_access_and_get_org_member_info(user, required_org_id)
    
    def validate_minimum_org_role_and_get_org(self, user: User, required_org_id: str, minimum_role: str):
        return validate_minimum_org_role_and_get_org(user, required_org_id, minimum_role)
    
    def validate_exact_org_role_and_get_org(self, user: User, required_org_id: str, exact_role: str):
        return validate_exact_org_role_and_get_org(user, required_org_id, exact_role)
    
    def validate_permission_and_get_org(self, user: User, required_org_id: str, permission: str):
        return validate_permission_and_get_org(user, required_org_id, permission)
    
    def validate_all_permissions_and_get_org(self, user: User, required_org_id: str, permissions: List[str]):
        return validate_all_permissions_and_get_org(user, required_org_id, permissions)
    


def init_base_auth(
    auth_url: str,
    integration_api_key: str,
    token_verification_metadata: Optional[TokenVerificationMetadata] = None,
) -> Auth:
    auth_hostname = _validate_and_extract_auth_hostname(auth_url)
    token_verification_metadata = _fetch_token_verification_metadata(
        auth_hostname, integration_api_key, token_verification_metadata
    )
    return Auth(auth_hostname, integration_api_key, token_verification_metadata)