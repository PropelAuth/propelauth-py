import asyncio
import httpx
from typing import Optional, Any, Dict, List
from propelauth_py.user import UserAndOrgMemberInfo, User
from propelauth_py.jwt import _validate_access_token_and_get_user
from propelauth_py.api import (
    token_verification_metadata,
    TokenVerificationMetadata,
    OrgQueryOrderBy,
    UserQueryOrderBy,
)
from propelauth_py.api.user import (
    _clear_user_password,
    _clear_user_password_async,
    _fetch_user_metadata_by_user_id,
    _fetch_user_metadata_by_user_id_async,
    _fetch_user_metadata_by_email,
    _fetch_user_metadata_by_email_async,
    _fetch_user_metadata_by_username,
    _fetch_user_metadata_by_username_async,
    _fetch_batch_user_metadata_by_user_ids,
    _fetch_batch_user_metadata_by_user_ids_async,
    _fetch_batch_user_metadata_by_emails,
    _fetch_batch_user_metadata_by_emails_async,
    _fetch_batch_user_metadata_by_usernames,
    _fetch_batch_user_metadata_by_usernames_async,
    _fetch_user_signup_query_params_by_user_id,
    _fetch_user_signup_query_params_by_user_id_async,
    _fetch_users_by_query,
    _fetch_users_by_query_async,
    _fetch_users_in_org,
    _fetch_users_in_org_async,
    _create_user,
    _create_user_async,
    _logout_all_user_sessions,
    _logout_all_user_sessions_async,
    _update_user_email,
    _update_user_email_async,
    _update_user_metadata,
    _update_user_metadata_async,
    _delete_user,
    _delete_user_async,
    _disable_user,
    _disable_user_async,
    _enable_user,
    _enable_user_async,
    _update_user_password,
    _update_user_password_async,
    _disable_user_2fa,
    _disable_user_2fa_async,
    _enable_user_can_create_orgs,
    _enable_user_can_create_orgs_async,
    _disable_user_can_create_orgs,
    _disable_user_can_create_orgs_async,
    _validate_personal_api_key,
    _validate_personal_api_key_async,
    _invite_user_to_org,
    _invite_user_to_org_async,
    _resend_email_confirmation,
    _resend_email_confirmation_async
)
from propelauth_py.api.access_token import _create_access_token, _create_access_token_async
from propelauth_py.api.end_user_api_keys import (
    _create_api_key,
    _create_api_key_async,
    _delete_api_key,
    _delete_api_key_async,
    _fetch_api_key,
    _fetch_api_key_async,
    _fetch_archived_api_keys,
    _fetch_archived_api_keys_async,
    _fetch_current_api_keys,
    _fetch_current_api_keys_async,
    _update_api_key,
    _update_api_key_async,
    _validate_api_key,
    _validate_api_key_async,
)
from propelauth_py.api.magic_link import _create_magic_link, _create_magic_link_async
from propelauth_py.api.migrate_user import (
    _migrate_user_from_external_source,
    _migrate_user_from_external_source_async,
    _migrate_user_password,
    _migrate_user_password_async,
)
from propelauth_py.api.step_up_mfa.verify_totp_challenge import (
    _verify_step_up_totp_challenge,
    _verify_step_up_totp_challenge_async
)
from propelauth_py.api.step_up_mfa.verify_grant import _verify_step_up_grant, _verify_step_up_grant_async
from propelauth_py.types.step_up_mfa import (
    StepUpMfaGrantType,
    StepUpMfaVerifyTotpResponse,
)
from propelauth_py.api.org import (
    _add_user_to_org,
    _add_user_to_org_async,
    _allow_org_to_setup_saml_connection,
    _allow_org_to_setup_saml_connection_async,
    _change_user_role_in_org,
    _change_user_role_in_org_async,
    _create_org,
    _create_org_async,
    _create_org_saml_connection_link,
    _create_org_saml_connection_link_async,
    _delete_org,
    _delete_org_async,
    _disallow_org_to_setup_saml_connection,
    _disallow_org_to_setup_saml_connection_async,
    _fetch_custom_role_mappings,
    _fetch_custom_role_mappings_async,
    _fetch_org,
    _fetch_org_async,
    _fetch_org_by_query,
    _fetch_org_by_query_async,
    _fetch_pending_invites,
    _fetch_pending_invites_async,
    _remove_user_from_org,
    _remove_user_from_org_async,
    _revoke_pending_org_invite,
    _revoke_pending_org_invite_async,
    _subscribe_org_to_role_mapping,
    _subscribe_org_to_role_mapping_async,
    _update_org_metadata,
    _update_org_metadata_async,
    _validate_org_api_key,
    _validate_org_api_key_async,
    _fetch_saml_sp_metadata,
    _fetch_saml_sp_metadata_async,
    _set_saml_idp_metadata,
    _set_saml_idp_metadata_async,
    _saml_go_live,
    _saml_go_live_async,
    _delete_saml_connection,
    _delete_saml_connection_async,
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
    def __init__(
        self,
        auth_hostname: str,
        integration_api_key: str,
        token_verification_metadata: Optional[TokenVerificationMetadata],
    ):
        self.auth_hostname = auth_hostname
        self.integration_api_key = integration_api_key
        self.token_verification_metadata = token_verification_metadata

    def fetch_user_metadata_by_user_id(self, user_id: str, include_orgs: bool = False):
        return _fetch_user_metadata_by_user_id(
            self.auth_hostname, self.integration_api_key, user_id, include_orgs
        )

    def fetch_user_metadata_by_email(self, email: str, include_orgs: bool = False):
        return _fetch_user_metadata_by_email(
            self.auth_hostname, self.integration_api_key, email, include_orgs
        )

    def fetch_user_metadata_by_username(
        self, username: str, include_orgs: bool = False
    ):
        return _fetch_user_metadata_by_username(
            self.auth_hostname, self.integration_api_key, username, include_orgs
        )

    def fetch_user_signup_query_params_by_user_id(self, user_id: str):
        return _fetch_user_signup_query_params_by_user_id(
            self.auth_hostname, self.integration_api_key, user_id
        )

    def fetch_batch_user_metadata_by_user_ids(
        self, user_ids: List[str], include_orgs: bool = False
    ):
        return _fetch_batch_user_metadata_by_user_ids(
            self.auth_hostname, self.integration_api_key, user_ids, include_orgs
        )

    def fetch_batch_user_metadata_by_emails(
        self, emails: List[str], include_orgs: bool = False
    ):
        return _fetch_batch_user_metadata_by_emails(
            self.auth_hostname, self.integration_api_key, emails, include_orgs
        )

    def fetch_batch_user_metadata_by_usernames(
        self, usernames: List[str], include_orgs: bool = False
    ):
        return _fetch_batch_user_metadata_by_usernames(
            self.auth_hostname, self.integration_api_key, usernames, include_orgs
        )

    def fetch_org(self, org_id: str):
        return _fetch_org(self.auth_hostname, self.integration_api_key, org_id)

    def fetch_org_by_query(
        self,
        page_size: int = 10,
        page_number: int = 0,
        order_by: OrgQueryOrderBy = OrgQueryOrderBy.CREATED_AT_ASC,
        name: Optional[str] = None,
        legacy_org_id: Optional[str] = None,
        domain: Optional[str] = None,
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

    def fetch_pending_invites(
        self, page_number: int = 0, page_size: int = 10, org_id: Optional[str] = None
    ):
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
        legacy_user_id: Optional[str] = None,
    ):
        return _fetch_users_by_query(
            self.auth_hostname,
            self.integration_api_key,
            page_size,
            page_number,
            order_by,
            email_or_username,
            include_orgs,
            legacy_user_id,
        )

    def fetch_users_in_org(
        self,
        org_id: str,
        page_size: int = 10,
        page_number: int = 0,
        include_orgs: bool = False,
        role: Optional[str] = None,
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
        ignore_domain_restrictions: bool = False,
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
            ignore_domain_restrictions,
        )

    def invite_user_to_org(
        self, email: str, org_id: str, role: str, additional_roles: List[str] = []
    ):
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

    def update_user_email(
        self, user_id: str, new_email: str, require_email_confirmation: bool
    ):
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
            legacy_user_id=legacy_user_id,
        )

    def clear_user_password(self, user_id: str):
        return _clear_user_password(
            self.auth_hostname, self.integration_api_key, user_id
        )

    def update_user_password(
        self,
        user_id: str,
        password: str,
        ask_user_to_update_password_on_login: bool = False,
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
        active_org_id: Optional[str] = None,
    ):
        return _create_access_token(
            self.auth_hostname,
            self.integration_api_key,
            user_id,
            duration_in_minutes,
            active_org_id,
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
            self.auth_hostname, self.integration_api_key, user_id, password_hash
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
            extra_domains=extra_domains,
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
        return _revoke_pending_org_invite(
            self.auth_hostname, self.integration_api_key, org_id, invitee_email
        )

    def add_user_to_org(
        self, user_id: str, org_id: str, role: str, additional_roles: List[str] = []
    ):
        return _add_user_to_org(
            self.auth_hostname,
            self.integration_api_key,
            user_id,
            org_id,
            role,
            additional_roles,
        )

    def remove_user_from_org(self, user_id: str, org_id: str):
        return _remove_user_from_org(
            self.auth_hostname, self.integration_api_key, user_id, org_id
        )

    def change_user_role_in_org(
        self, user_id: str, org_id: str, role: str, additional_roles: List[str] = []
    ):
        return _change_user_role_in_org(
            self.auth_hostname,
            self.integration_api_key,
            user_id,
            org_id,
            role,
            additional_roles,
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
        return _enable_user_can_create_orgs(
            self.auth_hostname, self.integration_api_key, user_id
        )

    def disable_user_can_create_orgs(self, user_id: str):
        return _disable_user_can_create_orgs(
            self.auth_hostname, self.integration_api_key, user_id
        )

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
        self,
        org_id: Optional[str] = None,
        user_id: Optional[str] = None,
        expires_at_seconds: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        return _create_api_key(
            self.auth_hostname,
            self.integration_api_key,
            org_id,
            user_id,
            expires_at_seconds,
            metadata,
        )

    def update_api_key(
        self,
        api_key_id: str,
        expires_at_seconds: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        return _update_api_key(
            self.auth_hostname,
            self.integration_api_key,
            api_key_id,
            expires_at_seconds,
            metadata,
        )

    def delete_api_key(self, api_key_id: str):
        return _delete_api_key(self.auth_hostname, self.integration_api_key, api_key_id)

    def validate_personal_api_key(self, api_key_token: str):
        return _validate_personal_api_key(
            self.auth_hostname, self.integration_api_key, api_key_token
        )

    def validate_org_api_key(self, api_key_token: str):
        return _validate_org_api_key(
            self.auth_hostname, self.integration_api_key, api_key_token
        )

    def validate_api_key(self, api_key_token: str):
        return _validate_api_key(
            self.auth_hostname, self.integration_api_key, api_key_token
        )

    def verify_step_up_totp_challenge(
        self,
        action_type: str,
        user_id: str,
        code: str,
        grant_type: StepUpMfaGrantType,
        valid_for_seconds: int,
    ) -> StepUpMfaVerifyTotpResponse:
        """Verify a TOTP code for step-up MFA authentication.

        This function verifies if the provided TOTP code is valid for the given user and returns a grant
        that can be verified for future sensitive operations.

        Args:
            action_type: Identifier for the type of action requiring step-up verification
            user_id: ID of the user performing the action
            code: The TOTP code provided by the user
            grant_type: Type of grant to generate (ONE_TIME_USE or TIME_BASED)
            valid_for_seconds: How long the verification grant should be valid for

        Returns:
            StepUpMfaVerifyTotpResponse: Response containing the step_up_grant

        Raises:
            UserNotFoundException: If the user doesn't exist
            MfaNotEnabledException: If MFA is not enabled for the user
            IncorrectMfaCodeException: If the provided TOTP code is incorrect
            FeatureGatedException: If step-up MFA is not allowed on your current pricing plan
            BadRequestException: If there are validation errors with the input parameters
            RateLimitedException: If too many requests are made in a short period
            ValueError: If the integration_api_key is incorrect
            RuntimeError: For unknown errors
        """
        return _verify_step_up_totp_challenge(
            self.auth_hostname,
            self.integration_api_key,
            action_type,
            user_id,
            code,
            grant_type,
            valid_for_seconds,
        )

    def verify_step_up_grant(self, action_type: str, user_id: str, grant: str) -> bool:
        """Verify a step-up MFA grant for a sensitive operation.

        This function verifies if the provided grant is valid for the given user and action type.

        Args:
            action_type: Identifier for the type of action requiring step-up verification
            user_id: ID of the user performing the action
            grant: The step-up grant to verify (obtained from verify_step_up_totp_challenge)

        Returns:
            bool: True if the grant is valid, False if not found

        Raises:
            FeatureGatedException: If step-up MFA is not allowed on your current pricing plan
            BadRequestException: If there are validation errors with the input parameters
            RateLimitedException: If too many requests are made in a short period
            ValueError: If the integration_api_key is incorrect
            RuntimeError: For unknown errors
        """
        return _verify_step_up_grant(
            self.auth_hostname, self.integration_api_key, action_type, user_id, grant
        )

    def validate_access_token_and_get_user(self, authorization_header: Optional[str]):
        access_token = _extract_token_from_authorization_header(authorization_header)
        user = _validate_access_token_and_get_user(
            access_token, self.token_verification_metadata
        )
        return user

    def validate_access_token_and_get_user_with_org(
        self, authorization_header: Optional[str], required_org_id: str
    ):
        access_token = _extract_token_from_authorization_header(authorization_header)
        user = _validate_access_token_and_get_user(
            access_token, self.token_verification_metadata
        )
        org_member_info = validate_org_access_and_get_org_member_info(
            user, required_org_id
        )
        return UserAndOrgMemberInfo(user, org_member_info)

    def validate_access_token_and_get_user_with_org_by_minimum_role(
        self,
        authorization_header: Optional[str],
        required_org_id: str,
        minimum_required_role: str,
    ):
        access_token = _extract_token_from_authorization_header(authorization_header)
        user = _validate_access_token_and_get_user(
            access_token, self.token_verification_metadata
        )
        org_member_info = validate_minimum_org_role_and_get_org(
            user, required_org_id, minimum_required_role
        )
        return UserAndOrgMemberInfo(user, org_member_info)

    def validate_access_token_and_get_user_with_org_by_exact_role(
        self,
        authorization_header: Optional[str],
        required_org_id: str,
        required_role: str,
    ):
        access_token = _extract_token_from_authorization_header(authorization_header)
        user = _validate_access_token_and_get_user(
            access_token, self.token_verification_metadata
        )
        org_member_info = validate_exact_org_role_and_get_org(
            user, required_org_id, required_role
        )
        return UserAndOrgMemberInfo(user, org_member_info)

    def validate_access_token_and_get_user_with_org_by_permission(
        self, authorization_header: Optional[str], required_org_id: str, permission: str
    ):
        access_token = _extract_token_from_authorization_header(authorization_header)
        user = _validate_access_token_and_get_user(
            access_token, self.token_verification_metadata
        )
        org_member_info = validate_permission_and_get_org(
            user, required_org_id, permission
        )
        return UserAndOrgMemberInfo(user, org_member_info)

    def validate_access_token_and_get_user_with_org_by_all_permissions(
        self,
        authorization_header: Optional[str],
        required_org_id: str,
        permissions: List[str],
    ):
        access_token = _extract_token_from_authorization_header(authorization_header)
        user = _validate_access_token_and_get_user(
            access_token, self.token_verification_metadata
        )
        org_member_info = validate_all_permissions_and_get_org(
            user, required_org_id, permissions
        )
        return UserAndOrgMemberInfo(user, org_member_info)

    def validate_org_access_and_get_org(self, user: User, required_org_id: str):
        return validate_org_access_and_get_org_member_info(user, required_org_id)

    def validate_minimum_org_role_and_get_org(
        self, user: User, required_org_id: str, minimum_role: str
    ):
        return validate_minimum_org_role_and_get_org(
            user, required_org_id, minimum_role
        )

    def validate_exact_org_role_and_get_org(
        self, user: User, required_org_id: str, exact_role: str
    ):
        return validate_exact_org_role_and_get_org(user, required_org_id, exact_role)

    def validate_permission_and_get_org(
        self, user: User, required_org_id: str, permission: str
    ):
        return validate_permission_and_get_org(user, required_org_id, permission)

    def validate_all_permissions_and_get_org(
        self, user: User, required_org_id: str, permissions: List[str]
    ):
        return validate_all_permissions_and_get_org(user, required_org_id, permissions)


class AsyncAuth(Auth):
    def __init__(
        self,
        auth_hostname: str,
        integration_api_key: str,
        token_verification_metadata: Optional[TokenVerificationMetadata],
        httpx_client: Optional[httpx.AsyncClient] = None,
    ):
        super().__init__(
            auth_hostname = auth_hostname, 
            integration_api_key = integration_api_key,
            token_verification_metadata = token_verification_metadata
        )

        self.is_httpx_client_provided = httpx_client is not None
        if httpx_client:
            self.httpx_client = httpx_client
        else:
            self.httpx_client = httpx.AsyncClient()
            self.is_httpx_client_provided = False
    
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type=None, exc_val=None, exc_tb=None):
        if not self.is_httpx_client_provided:
            await self.httpx_client.aclose()


    ####################
    #     API KEYS     #
    ####################

    async def validate_api_key(self, api_key_token: str):
        return await _validate_api_key_async(
            auth_hostname=self.auth_hostname,
            integration_api_key=self.integration_api_key,
            api_key_token=api_key_token,
            httpx_client=self.httpx_client,
        )
        
    async def fetch_api_key(
        self, 
        api_key_id: str
    ):
        return await _fetch_api_key_async(
            self.httpx_client, 
            self.auth_hostname, 
            self.integration_api_key, 
            api_key_id
        )
    
    async def fetch_current_api_keys(
        self,
        org_id: Optional[str] = None,
        user_id: Optional[str] = None,
        user_email: Optional[str] = None,
        page_size: Optional[int] = None,
        page_number: Optional[int] = None,
        api_key_type: Optional[str] = None,
    ):
        return await _fetch_current_api_keys_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            org_id,
            user_id,
            user_email,
            page_size,
            page_number,
            api_key_type,
        )
        
    async def fetch_archived_api_keys(
        self,
        org_id: Optional[str] = None,
        user_id: Optional[str] = None,
        user_email: Optional[str] = None,
        page_size: Optional[int] = None,
        page_number: Optional[int] = None,
        api_key_type: Optional[str] = None,
    ):
        return await _fetch_archived_api_keys_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            org_id,
            user_id,
            user_email,
            page_size,
            page_number,
            api_key_type=api_key_type,
        )
        
    async def create_api_key(
        self,
        org_id: Optional[str] = None,
        user_id: Optional[str] = None,
        expires_at_seconds: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        return await _create_api_key_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            org_id,
            user_id,
            expires_at_seconds,
            metadata,
        )
        
    async def update_api_key(
        self,
        api_key_id: str,
        expires_at_seconds: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        return await _update_api_key_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            api_key_id,
            expires_at_seconds,
            metadata,
        )
        
    async def delete_api_key(
        self,
        api_key_id: str
    ):
        return await _delete_api_key_async(
            self.httpx_client, 
            self.auth_hostname, 
            self.integration_api_key, 
            api_key_id
        )
    
    
    ####################
    #   Access Tokens  #
    ####################
    
    async def create_access_token(
        self,
        user_id: str,
        duration_in_minutes: int,
        active_org_id: Optional[str] = None,
    ):
        return await _create_access_token_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            user_id,
            duration_in_minutes,
            active_org_id,
        )
        
    ####################
    #    Magic Links   #
    ####################
    
    async def create_magic_link(
        self,
        email: str,
        redirect_to_url: Optional[str] = None,
        expires_in_hours: Optional[str] = None,
        create_new_user_if_one_doesnt_exist: Optional[bool] = None,
        user_signup_query_parameters: Optional[Dict[str, str]] = None,
    ):
        return await _create_magic_link_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            email,
            redirect_to_url,
            expires_in_hours,
            create_new_user_if_one_doesnt_exist,
            user_signup_query_parameters,
        )
        
    ####################
    #   Migrate User   #
    ####################
    
    async def migrate_user_from_external_source(
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
        return await _migrate_user_from_external_source_async(
            self.httpx_client,
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
        
    async def migrate_user_password(
        self,
        user_id: str,
        password_hash: str,
    ):
        return await _migrate_user_password_async(
            self.httpx_client,
            self.auth_hostname, 
            self.integration_api_key, 
            user_id, 
            password_hash
        )
        
    ####################
    #   Organizations  #
    ####################
    
    async def add_user_to_org(
        self, 
        user_id: str, 
        org_id: str, 
        role: str, 
        additional_roles: List[str] = []
    ):
        return await _add_user_to_org_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            user_id,
            org_id,
            role,
            additional_roles,
        )
        
    async def allow_org_to_setup_saml_connection(
        self, 
        org_id: str
    ):
        return await _allow_org_to_setup_saml_connection_async(
            self.httpx_client,
            self.auth_hostname, 
            self.integration_api_key, 
            org_id
        )
        
    async def change_user_role_in_org(
        self, 
        user_id: str, 
        org_id: str, 
        role: str, 
        additional_roles: List[str] = []
    ):
        return await _change_user_role_in_org_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            user_id,
            org_id,
            role,
            additional_roles,
        )
        
    async def create_org(
        self,
        name: str,
        enable_auto_joining_by_domain: bool = False,
        members_must_have_matching_domain: bool = False,
        domain: Optional[str] = None,
        max_users: Optional[str] = None,
        custom_role_mapping_name: Optional[str] = None,
        legacy_org_id: Optional[str] = None,
    ):
        return await _create_org_async(
            self.httpx_client,
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
        
    async def create_org_saml_connection_link(
        self, 
        org_id: str, 
        expires_in_seconds=None
    ):
        return await _create_org_saml_connection_link_async(
            self.httpx_client,
            self.auth_hostname, 
            self.integration_api_key, 
            org_id, 
            expires_in_seconds,
        )
        
    async def delete_org(
        self, 
        org_id: str
    ):
        return await _delete_org_async(
            self.httpx_client,
            self.auth_hostname, 
            self.integration_api_key, org_id
        )
        
    async def disallow_org_to_setup_saml_connection(
        self, 
        org_id: str
    ):
        return await _disallow_org_to_setup_saml_connection_async(
            self.httpx_client,
            self.auth_hostname, 
            self.integration_api_key,
            org_id
        )
        
    async def fetch_custom_role_mappings(self):
        return await _fetch_custom_role_mappings_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
        )
        
    async def fetch_org(
        self, 
        org_id: str
    ):
        return await _fetch_org_async(
            self.httpx_client,
            self.auth_hostname, 
            self.integration_api_key, 
            org_id
        )
        
    async def fetch_org_by_query(
        self,
        page_size: int = 10,
        page_number: int = 0,
        order_by: OrgQueryOrderBy = OrgQueryOrderBy.CREATED_AT_ASC,
        name: Optional[str] = None,
        legacy_org_id: Optional[str] = None,
        domain: Optional[str] = None,
    ):
        return await _fetch_org_by_query_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            page_size,
            page_number,
            order_by,
            name,
            legacy_org_id,
            domain,
        )

    async def fetch_pending_invites(
        self, 
        page_number: int = 0,
        page_size: int = 10,
        org_id: Optional[str] = None
    ):
        return await _fetch_pending_invites_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            page_number,
            page_size,
            org_id,
        )
        
    async def remove_user_from_org(
        self,
        user_id: str,
        org_id: str
    ):
        return await _remove_user_from_org_async(
            self.httpx_client,
            self.auth_hostname, 
            self.integration_api_key,
            user_id,
            org_id
        )
        
    async def revoke_pending_org_invite(
        self,
        org_id: str,
        invitee_email: str
    ):
        return await _revoke_pending_org_invite_async(
            self.httpx_client,
            self.auth_hostname, 
            self.integration_api_key,
            org_id,
            invitee_email
        )
        
    async def subscribe_org_to_role_mapping(
        self, 
        org_id: str, 
        custom_role_mapping_name: str
    ):
        return await _subscribe_org_to_role_mapping_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            org_id,
            custom_role_mapping_name,
        )
        
    async def update_org_metadata(
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
        return await _update_org_metadata_async(
            self.httpx_client,
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
            extra_domains=extra_domains,
        )
        
    async def validate_org_api_key(
        self,
        api_key_token: str
    ):
        return await _validate_org_api_key_async(
            self.httpx_client,
            self.auth_hostname, 
            self.integration_api_key,
            api_key_token
        )
        
    async def fetch_saml_sp_metadata(
        self, 
        org_id: str
    ):
        return await _fetch_saml_sp_metadata_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            org_id,
        )
        
    async def set_saml_idp_metadata(
        self, 
        org_id: str, 
        saml_idp_metadata: SamlIdpMetadata
    ):
        return await _set_saml_idp_metadata_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            org_id,
            saml_idp_metadata,
        )
        
    async def saml_go_live(
        self,
        org_id: str
    ):
        return await _saml_go_live_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            org_id,
        )
        
    async def delete_saml_connection(
        self,
        org_id: str
    ):
        return await _delete_saml_connection_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            org_id,
        )
        
    ####################
    #      Users       #
    ####################
    
    async def clear_user_password(self, user_id: str):
        return await _clear_user_password_async(
            self.httpx_client,
            self.auth_hostname, 
            self.integration_api_key,
            user_id
        )
        
    async def fetch_user_metadata_by_user_id(
        self, 
        user_id: str, 
        include_orgs: bool = False
    ):
        return await _fetch_user_metadata_by_user_id_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            user_id,
            include_orgs
        )
        
    async def fetch_user_metadata_by_email(
        self,
        email: str,
        include_orgs: bool = False
    ):
        return await _fetch_user_metadata_by_email_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            email,
            include_orgs
        )
        
    async def fetch_user_metadata_by_username(
        self, 
        username: str, 
        include_orgs: bool = False
    ):
        return await _fetch_user_metadata_by_username_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            username,
            include_orgs
        )
        
    async def fetch_batch_user_metadata_by_user_ids(
        self, 
        user_ids: List[str], 
        include_orgs: bool = False
    ):
        return await _fetch_batch_user_metadata_by_user_ids_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            user_ids,
            include_orgs
        )
        
    async def fetch_batch_user_metadata_by_emails(
        self,
        emails: List[str],
        include_orgs: bool = False
    ):
        return await _fetch_batch_user_metadata_by_emails_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            emails,
            include_orgs
        )
        
    async def fetch_batch_user_metadata_by_usernames(
        self, 
        usernames: List[str], 
        include_orgs: bool = False
    ):
        return await _fetch_batch_user_metadata_by_usernames_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            usernames,
            include_orgs
        )
        
    async def fetch_user_signup_query_params_by_user_id(self, user_id: str):
        return await _fetch_user_signup_query_params_by_user_id_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            user_id
        )
        
    async def fetch_users_by_query(
        self,
        page_size: int = 10,
        page_number: int = 0,
        order_by: UserQueryOrderBy = UserQueryOrderBy.CREATED_AT_ASC,
        email_or_username: Optional[str] = None,
        include_orgs: bool = False,
        legacy_user_id: Optional[str] = None,
    ):
        return await _fetch_users_by_query_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            page_size,
            page_number,
            order_by,
            email_or_username,
            include_orgs,
            legacy_user_id,
        )
        
    async def fetch_users_in_org(
        self,
        org_id: str,
        page_size: int = 10,
        page_number: int = 0,
        include_orgs: bool = False,
        role: Optional[str] = None,
    ):
        return await _fetch_users_in_org_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            org_id,
            page_size,
            page_number,
            include_orgs,
            role,
        )
        
    async def create_user(
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
        ignore_domain_restrictions: bool = False,
    ):
        return await _create_user_async(
            self.httpx_client,
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
            ignore_domain_restrictions,
        )
        
    async def logout_all_user_sessions(self, user_id: str):
        return await _logout_all_user_sessions_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            user_id,
        )
        
    async def update_user_email(
        self,
        user_id: str,
        new_email: str,
        require_email_confirmation: bool
    ):
        return await _update_user_email_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            user_id,
            new_email,
            require_email_confirmation,
        )

    async def update_user_metadata(
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
        return await _update_user_metadata_async(
            self.httpx_client,
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
            legacy_user_id=legacy_user_id,
        )
        
    async def delete_user(self, user_id: str):
        return await _delete_user_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            user_id
        )

    async def disable_user(self, user_id: str):
        return await _disable_user_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            user_id
        )

    async def enable_user(self, user_id: str):
        return await _enable_user_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            user_id
        )

    async def disable_user_2fa(self, user_id: str):
        return await _disable_user_2fa_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            user_id
        )
        
    async def update_user_password(
        self,
        user_id: str,
        password: str,
        ask_user_to_update_password_on_login: bool = False,
    ):
        return await _update_user_password_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            user_id,
            password,
            ask_user_to_update_password_on_login,
        )
        
    async def enable_user_can_create_orgs(self, user_id: str):
        return await _enable_user_can_create_orgs_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            user_id
        )

    async def disable_user_can_create_orgs(self, user_id: str):
        return await _disable_user_can_create_orgs_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            user_id
        )
        
    async def validate_personal_api_key(self, api_key_token: str):
        return await _validate_personal_api_key_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            api_key_token
        )
        
    async def invite_user_to_org(
        self, 
        email: str, 
        org_id: str, 
        role: str, 
        additional_roles: List[str] = []
    ):
        return await _invite_user_to_org_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            email,
            org_id,
            role,
            additional_roles,
        )

    async def resend_email_confirmation(self, user_id: str):
        return await _resend_email_confirmation_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            user_id,
        )
        
    ####################
    #    Step Up MFA   #
    ####################
    
    async def verify_step_up_grant(self, action_type: str, user_id: str, grant: str) -> bool:
        """Verify a step-up MFA grant for a sensitive operation.

        This function verifies if the provided grant is valid for the given user and action type.

        Args:
            action_type: Identifier for the type of action requiring step-up verification
            user_id: ID of the user performing the action
            grant: The step-up grant to verify (obtained from verify_step_up_totp_challenge)

        Returns:
            bool: True if the grant is valid, False if not found

        Raises:
            FeatureGatedException: If step-up MFA is not allowed on your current pricing plan
            BadRequestException: If there are validation errors with the input parameters
            RateLimitedException: If too many requests are made in a short period
            ValueError: If the integration_api_key is incorrect
            RuntimeError: For unknown errors
        """
        return await _verify_step_up_grant_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            action_type,
            user_id,
            grant
        )
        
    async def verify_step_up_totp_challenge(
        self,
        action_type: str,
        user_id: str,
        code: str,
        grant_type: StepUpMfaGrantType,
        valid_for_seconds: int,
    ) -> StepUpMfaVerifyTotpResponse:
        """Verify a TOTP code for step-up MFA authentication.

        This function verifies if the provided TOTP code is valid for the given user and returns a grant
        that can be verified for future sensitive operations.

        Args:
            action_type: Identifier for the type of action requiring step-up verification
            user_id: ID of the user performing the action
            code: The TOTP code provided by the user
            grant_type: Type of grant to generate (ONE_TIME_USE or TIME_BASED)
            valid_for_seconds: How long the verification grant should be valid for

        Returns:
            StepUpMfaVerifyTotpResponse: Response containing the step_up_grant

        Raises:
            UserNotFoundException: If the user doesn't exist
            MfaNotEnabledException: If MFA is not enabled for the user
            IncorrectMfaCodeException: If the provided TOTP code is incorrect
            FeatureGatedException: If step-up MFA is not allowed on your current pricing plan
            BadRequestException: If there are validation errors with the input parameters
            RateLimitedException: If too many requests are made in a short period
            ValueError: If the integration_api_key is incorrect
            RuntimeError: For unknown errors
        """
        return await _verify_step_up_totp_challenge_async(
            self.httpx_client,
            self.auth_hostname,
            self.integration_api_key,
            action_type,
            user_id,
            code,
            grant_type,
            valid_for_seconds,
        )

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


def init_base_async_auth(
    auth_url: str,
    integration_api_key: str,
    token_verification_metadata: Optional[TokenVerificationMetadata] = None,
    httpx_client: Optional[httpx.AsyncClient] = None,
) -> AsyncAuth:
    auth_hostname = _validate_and_extract_auth_hostname(auth_url)
    token_verification_metadata = _fetch_token_verification_metadata(
        auth_hostname, integration_api_key, token_verification_metadata
    )
    return AsyncAuth(auth_hostname, integration_api_key, token_verification_metadata, httpx_client)