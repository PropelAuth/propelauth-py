from collections import namedtuple

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
)
from propelauth_py.api.org import (
    _fetch_org,
    _fetch_org_by_query,
    _create_org,
    _remove_user_from_org,
    _update_org_metadata,
    _add_user_to_org,
    _allow_org_to_setup_saml_connection,
    _disallow_org_to_setup_saml_connection,
    _validate_org_api_key,
    _change_user_role_in_org,
    _delete_org,
)
from propelauth_py.api.magic_link import _create_magic_link
from propelauth_py.api.token_verification_metadata import (
    _fetch_token_verification_metadata,
)
from propelauth_py.api.access_token import _create_access_token
from propelauth_py.api.migrate_user import _migrate_user_from_external_source
from propelauth_py.api.end_user_api_keys import (
    _fetch_api_key,
    _fetch_current_api_keys,
    _fetch_archived_api_keys,
    _create_api_key,
    _update_api_key,
    _delete_api_key,
    _validate_api_key,
)
from propelauth_py.api import (
    OrgQueryOrderBy,
    UserQueryOrderBy,
    TokenVerificationMetadata,
)
from propelauth_py.auth_fns import (
    wrap_validate_access_token_and_get_user,
    wrap_validate_access_token_and_get_user_with_org,
    wrap_validate_access_token_and_get_user_with_org_by_minimum_role,
    wrap_validate_access_token_and_get_user_with_org_by_exact_role,
    wrap_validate_access_token_and_get_user_with_org_by_permission,
    wrap_validate_access_token_and_get_user_with_org_by_all_permissions,
    validate_org_access_and_get_org_member_info,
    validate_minimum_org_role_and_get_org,
    validate_exact_org_role_and_get_org,
    validate_permission_and_get_org,
    validate_all_permissions_and_get_org,
)
from propelauth_py.errors import UnauthorizedException, ForbiddenException
from propelauth_py.validation import _validate_url

Auth = namedtuple(
    "Auth",
    [
        "validate_access_token_and_get_user",
        "validate_access_token_and_get_user_with_org",
        "validate_access_token_and_get_user_with_org_by_minimum_role",
        "validate_access_token_and_get_user_with_org_by_exact_role",
        "validate_access_token_and_get_user_with_org_by_permission",
        "validate_access_token_and_get_user_with_org_by_all_permissions",
        "validate_org_access_and_get_org",
        "validate_minimum_org_role_and_get_org",
        "validate_exact_org_role_and_get_org",
        "validate_permission_and_get_org",
        "validate_all_permissions_and_get_org",
        "fetch_user_metadata_by_user_id",
        "fetch_user_metadata_by_email",
        "fetch_user_metadata_by_username",
        "fetch_user_signup_query_params_by_user_id",
        "fetch_batch_user_metadata_by_user_ids",
        "fetch_batch_user_metadata_by_emails",
        "fetch_batch_user_metadata_by_usernames",
        "fetch_org",
        "fetch_org_by_query",
        "fetch_users_by_query",
        "fetch_users_in_org",
        "create_user",
        "invite_user_to_org",
        "update_user_email",
        "update_user_metadata",
        "update_user_password",
        "clear_user_password",
        "create_magic_link",
        "create_access_token",
        "migrate_user_from_external_source",
        "create_org",
        "delete_org",
        "update_org_metadata",
        "add_user_to_org",
        "change_user_role_in_org",
        "remove_user_from_org",
        "delete_user",
        "disable_user",
        "enable_user",
        "disable_user_2fa",
        "enable_user_can_create_orgs",
        "disable_user_can_create_orgs",
        "allow_org_to_setup_saml_connection",
        "disallow_org_to_setup_saml_connection",
        "fetch_api_key",
        "fetch_current_api_keys",
        "fetch_archived_api_keys",
        "create_api_key",
        "update_api_key",
        "delete_api_key",
        "validate_personal_api_key",
        "validate_org_api_key",
        "validate_api_key",
    ],
)


def init_base_auth(
    auth_url: str,
    integration_api_key: str,
    token_verification_metadata: TokenVerificationMetadata = None,
) -> Auth:
    """Fetches metadata required to validate access tokens and returns auth decorators and utilities"""
    auth_url = _validate_url(auth_url)
    token_verification_metadata = _fetch_token_verification_metadata(
        auth_url, integration_api_key, token_verification_metadata
    )

    def fetch_user_metadata_by_user_id(user_id, include_orgs=False):
        return _fetch_user_metadata_by_user_id(
            auth_url, integration_api_key, user_id, include_orgs
        )

    def fetch_user_metadata_by_email(email, include_orgs=False):
        return _fetch_user_metadata_by_email(
            auth_url, integration_api_key, email, include_orgs
        )

    def fetch_user_metadata_by_username(username, include_orgs=False):
        return _fetch_user_metadata_by_username(
            auth_url, integration_api_key, username, include_orgs
        )

    def fetch_user_signup_query_params_by_user_id(user_id):
        return _fetch_user_signup_query_params_by_user_id(
            auth_url, integration_api_key, user_id
        )

    def fetch_batch_user_metadata_by_user_ids(user_ids, include_orgs=False):
        return _fetch_batch_user_metadata_by_user_ids(
            auth_url, integration_api_key, user_ids, include_orgs
        )

    def fetch_batch_user_metadata_by_emails(emails, include_orgs=False):
        return _fetch_batch_user_metadata_by_emails(
            auth_url, integration_api_key, emails, include_orgs
        )

    def fetch_batch_user_metadata_by_usernames(usernames, include_orgs=False):
        return _fetch_batch_user_metadata_by_usernames(
            auth_url, integration_api_key, usernames, include_orgs
        )

    def fetch_org(org_id):
        return _fetch_org(auth_url, integration_api_key, org_id)

    def fetch_org_by_query(
        page_size=10, page_number=0, order_by=OrgQueryOrderBy.CREATED_AT_ASC, name=None
    ):
        return _fetch_org_by_query(
            auth_url,
            integration_api_key,
            page_size,
            page_number,
            order_by,
            name,
        )

    def fetch_users_by_query(
        page_size=10,
        page_number=0,
        order_by=UserQueryOrderBy.CREATED_AT_ASC,
        email_or_username=None,
        include_orgs=False,
    ):
        return _fetch_users_by_query(
            auth_url,
            integration_api_key,
            page_size,
            page_number,
            order_by,
            email_or_username,
            include_orgs,
        )

    def fetch_users_in_org(
        org_id, page_size=10, page_number=0, include_orgs=False, role=None
    ):
        return _fetch_users_in_org(
            auth_url,
            integration_api_key,
            org_id,
            page_size,
            page_number,
            include_orgs,
            role,
        )

    def create_user(
        email,
        email_confirmed=False,
        send_email_to_confirm_email_address=True,
        ask_user_to_update_password_on_login=False,
        password=None,
        username=None,
        first_name=None,
        last_name=None,
        properties=None,
    ):
        return _create_user(
            auth_url,
            integration_api_key,
            email,
            email_confirmed,
            send_email_to_confirm_email_address,
            ask_user_to_update_password_on_login,
            password,
            username,
            first_name,
            last_name,
            properties,
        )

    def invite_user_to_org(email, org_id, role):
        return _invite_user_to_org(
            auth_url,
            integration_api_key,
            email,
            org_id,
            role,
        )

    def update_user_email(user_id, new_email, require_email_confirmation):
        return _update_user_email(
            auth_url,
            integration_api_key,
            user_id,
            new_email,
            require_email_confirmation,
        )

    def update_user_metadata(
        user_id,
        username=None,
        first_name=None,
        last_name=None,
        metadata=None,
        properties=None,
        picture_url=None,
        update_password_required=None,
    ):
        return _update_user_metadata(
            auth_url,
            integration_api_key,
            user_id=user_id,
            username=username,
            first_name=first_name,
            last_name=last_name,
            metadata=metadata,
            properties=properties,
            picture_url=picture_url,
            update_password_required=update_password_required,
        )

    def clear_user_password(user_id):
        return _clear_user_password(auth_url, integration_api_key, user_id)

    def update_user_password(
        user_id, password, ask_user_to_update_password_on_login=False
    ):
        return _update_user_password(
            auth_url,
            integration_api_key,
            user_id,
            password,
            ask_user_to_update_password_on_login,
        )

    def create_magic_link(
        email,
        redirect_to_url=None,
        expires_in_hours=None,
        create_new_user_if_one_doesnt_exist=None,
        user_signup_query_parameters=None,
    ):
        return _create_magic_link(
            auth_url,
            integration_api_key,
            email,
            redirect_to_url,
            expires_in_hours,
            create_new_user_if_one_doesnt_exist,
            user_signup_query_parameters,
        )

    def create_access_token(user_id, duration_in_minutes):
        return _create_access_token(
            auth_url, integration_api_key, user_id, duration_in_minutes
        )

    def migrate_user_from_external_source(
        email,
        email_confirmed,
        existing_user_id=None,
        existing_password_hash=None,
        existing_mfa_base32_encoded_secret=None,
        ask_user_to_update_password_on_login=False,
        enabled=None,
        first_name=None,
        last_name=None,
        username=None,
        properties=None,
    ):
        return _migrate_user_from_external_source(
            auth_url,
            integration_api_key,
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
            properties,
        )

    def create_org(
        name,
        enable_auto_joining_by_domain=False,
        members_must_have_matching_domain=False,
        domain=None,
        max_users=None,
    ):
        return _create_org(
            auth_url,
            integration_api_key,
            name,
            enable_auto_joining_by_domain,
            members_must_have_matching_domain,
            domain,
            max_users,
        )

    def update_org_metadata(
        org_id,
        name=None,
        can_setup_saml=None,
        metadata=None,
        max_users=None,
        can_join_on_email_domain_match=None,
        members_must_have_email_domain_match=None,
        domain=None,
    ):
        return _update_org_metadata(
            auth_url,
            integration_api_key,
            org_id=org_id,
            name=name,
            can_setup_saml=can_setup_saml,
            metadata=metadata,
            max_users=max_users,
            can_join_on_email_domain_match=can_join_on_email_domain_match,
            members_must_have_email_domain_match=members_must_have_email_domain_match,
            domain=domain,
        )

    def delete_org(org_id):
        return _delete_org(auth_url, integration_api_key, org_id)

    def add_user_to_org(user_id, org_id, role):
        return _add_user_to_org(auth_url, integration_api_key, user_id, org_id, role)

    def remove_user_from_org(user_id, org_id):
        return _remove_user_from_org(auth_url, integration_api_key, user_id, org_id)

    def change_user_role_in_org(user_id, org_id, role):
        return _change_user_role_in_org(
            auth_url, integration_api_key, user_id, org_id, role
        )

    def delete_user(user_id):
        return _delete_user(auth_url, integration_api_key, user_id)

    def disable_user(user_id):
        return _disable_user(auth_url, integration_api_key, user_id)

    def enable_user(user_id):
        return _enable_user(auth_url, integration_api_key, user_id)

    def disable_user_2fa(user_id):
        return _disable_user_2fa(auth_url, integration_api_key, user_id)

    def enable_user_can_create_orgs(user_id):
        return _enable_user_can_create_orgs(auth_url, integration_api_key, user_id)

    def disable_user_can_create_orgs(user_id):
        return _disable_user_can_create_orgs(auth_url, integration_api_key, user_id)

    def allow_org_to_setup_saml_connection(org_id):
        return _allow_org_to_setup_saml_connection(
            auth_url, integration_api_key, org_id
        )

    def disallow_org_to_setup_saml_connection(org_id):
        return _disallow_org_to_setup_saml_connection(
            auth_url, integration_api_key, org_id
        )

    # functions for end user api keys

    def fetch_api_key(api_key_id):
        return _fetch_api_key(auth_url, integration_api_key, api_key_id)

    def fetch_current_api_keys(
        org_id=None,
        user_id=None,
        user_email=None,
        page_size=None,
        page_number=None,
        api_key_type=None,
    ):
        return _fetch_current_api_keys(
            auth_url,
            integration_api_key,
            org_id,
            user_id,
            user_email,
            page_size,
            page_number,
            api_key_type,
        )

    def fetch_archived_api_keys(
        org_id=None,
        user_id=None,
        user_email=None,
        page_size=None,
        page_number=None,
        api_key_type=None,
    ):
        return _fetch_archived_api_keys(
            auth_url,
            integration_api_key,
            org_id,
            user_id,
            user_email,
            page_size,
            page_number,
            api_key_type=api_key_type,
        )

    def create_api_key(
        org_id=None, user_id=None, expires_at_seconds=None, metadata=None
    ):
        return _create_api_key(
            auth_url, integration_api_key, org_id, user_id, expires_at_seconds, metadata
        )

    def update_api_key(api_key_id, expires_at_seconds=None, metadata=None):
        return _update_api_key(
            auth_url, integration_api_key, api_key_id, expires_at_seconds, metadata
        )

    def delete_api_key(api_key_id):
        return _delete_api_key(auth_url, integration_api_key, api_key_id)

    def validate_personal_api_key(api_key_token):
        return _validate_personal_api_key(auth_url, integration_api_key, api_key_token)

    def validate_org_api_key(api_key_token):
        return _validate_org_api_key(auth_url, integration_api_key, api_key_token)

    def validate_api_key(api_key_token):
        return _validate_api_key(auth_url, integration_api_key, api_key_token)

    validate_access_token_and_get_user = wrap_validate_access_token_and_get_user(
        token_verification_metadata
    )

    validate_access_token_and_get_user_with_org = (
        wrap_validate_access_token_and_get_user_with_org(token_verification_metadata)
    )

    validate_access_token_and_get_user_with_org_by_minimum_role = (
        wrap_validate_access_token_and_get_user_with_org_by_minimum_role(
            token_verification_metadata
        )
    )

    validate_access_token_and_get_user_with_org_by_exact_role = (
        wrap_validate_access_token_and_get_user_with_org_by_exact_role(
            token_verification_metadata
        )
    )

    validate_access_token_and_get_user_with_org_by_permission = (
        wrap_validate_access_token_and_get_user_with_org_by_permission(
            token_verification_metadata
        )
    )

    validate_access_token_and_get_user_with_org_by_all_permissions = (
        wrap_validate_access_token_and_get_user_with_org_by_all_permissions(
            token_verification_metadata
        )
    )

    return Auth(
        # validation functions
        validate_org_access_and_get_org=validate_org_access_and_get_org_member_info,
        validate_minimum_org_role_and_get_org=validate_minimum_org_role_and_get_org,
        validate_exact_org_role_and_get_org=validate_exact_org_role_and_get_org,
        validate_permission_and_get_org=validate_permission_and_get_org,
        validate_all_permissions_and_get_org=validate_all_permissions_and_get_org,
        # wrappers for the validation functions
        validate_access_token_and_get_user=validate_access_token_and_get_user,
        validate_access_token_and_get_user_with_org=validate_access_token_and_get_user_with_org,
        validate_access_token_and_get_user_with_org_by_minimum_role=validate_access_token_and_get_user_with_org_by_minimum_role,
        validate_access_token_and_get_user_with_org_by_exact_role=validate_access_token_and_get_user_with_org_by_exact_role,
        validate_access_token_and_get_user_with_org_by_permission=validate_access_token_and_get_user_with_org_by_permission,
        validate_access_token_and_get_user_with_org_by_all_permissions=validate_access_token_and_get_user_with_org_by_all_permissions,
        fetch_user_metadata_by_user_id=fetch_user_metadata_by_user_id,
        fetch_user_metadata_by_email=fetch_user_metadata_by_email,
        fetch_user_metadata_by_username=fetch_user_metadata_by_username,
        fetch_user_signup_query_params_by_user_id=fetch_user_signup_query_params_by_user_id,
        fetch_batch_user_metadata_by_user_ids=fetch_batch_user_metadata_by_user_ids,
        fetch_batch_user_metadata_by_emails=fetch_batch_user_metadata_by_emails,
        fetch_batch_user_metadata_by_usernames=fetch_batch_user_metadata_by_usernames,
        fetch_org=fetch_org,
        fetch_org_by_query=fetch_org_by_query,
        fetch_users_by_query=fetch_users_by_query,
        fetch_users_in_org=fetch_users_in_org,
        create_user=create_user,
        invite_user_to_org=invite_user_to_org,
        update_user_email=update_user_email,
        update_user_metadata=update_user_metadata,
        update_user_password=update_user_password,
        clear_user_password=clear_user_password,
        create_magic_link=create_magic_link,
        create_access_token=create_access_token,
        migrate_user_from_external_source=migrate_user_from_external_source,
        create_org=create_org,
        delete_org=delete_org,
        update_org_metadata=update_org_metadata,
        add_user_to_org=add_user_to_org,
        change_user_role_in_org=change_user_role_in_org,
        remove_user_from_org=remove_user_from_org,
        enable_user=enable_user,
        disable_user=disable_user,
        delete_user=delete_user,
        disable_user_2fa=disable_user_2fa,
        enable_user_can_create_orgs=enable_user_can_create_orgs,
        disable_user_can_create_orgs=disable_user_can_create_orgs,
        allow_org_to_setup_saml_connection=allow_org_to_setup_saml_connection,
        disallow_org_to_setup_saml_connection=disallow_org_to_setup_saml_connection,
        # api key functions
        fetch_api_key=fetch_api_key,
        fetch_current_api_keys=fetch_current_api_keys,
        fetch_archived_api_keys=fetch_archived_api_keys,
        create_api_key=create_api_key,
        update_api_key=update_api_key,
        delete_api_key=delete_api_key,
        validate_api_key=validate_api_key,
        validate_personal_api_key=validate_personal_api_key,
        validate_org_api_key=validate_org_api_key,
    )
