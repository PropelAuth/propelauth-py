from collections import namedtuple

from propelauth_py.api import _fetch_token_verification_metadata, TokenVerificationMetadata, \
    _fetch_user_metadata_by_user_id, \
    _fetch_user_metadata_by_email, _fetch_user_metadata_by_username, _fetch_batch_user_metadata_by_user_ids, \
    _fetch_batch_user_metadata_by_emails, _fetch_batch_user_metadata_by_usernames, OrgQueryOrderBy, UserQueryOrderBy, \
    _fetch_org, _fetch_org_by_query, _fetch_users_by_query, _fetch_users_in_org, _create_user, _update_user_email, \
    _update_user_metadata, _create_magic_link, _migrate_user_from_external_source, _create_org, _update_org_metadata, \
    _add_user_to_org, _delete_user, _disable_user, _enable_user, _allow_org_to_setup_saml_connection, \
    _disallow_org_to_setup_saml_connection, _update_user_password, _create_access_token
from propelauth_py.auth_fns import wrap_validate_access_token_and_get_user, \
    wrap_validate_access_token_and_get_user_with_org, \
    wrap_validate_access_token_and_get_user_with_org_by_minimum_role, \
    wrap_validate_access_token_and_get_user_with_org_by_exact_role, \
    wrap_validate_access_token_and_get_user_with_org_by_permission, \
    wrap_validate_access_token_and_get_user_with_org_by_all_permissions, \
    validate_org_access_and_get_org_member_info, \
    validate_minimum_org_role_and_get_org, \
    validate_exact_org_role_and_get_org, \
    validate_permission_and_get_org, \
    validate_all_permissions_and_get_org
from propelauth_py.errors import UnauthorizedException
from propelauth_py.validation import _validate_url

Auth = namedtuple("Auth", [
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
    "fetch_batch_user_metadata_by_user_ids",
    "fetch_batch_user_metadata_by_emails",
    "fetch_batch_user_metadata_by_usernames",
    "fetch_org",
    "fetch_org_by_query",
    "fetch_users_by_query",
    "fetch_users_in_org",
    "create_user",
    "update_user_email",
    "update_user_metadata",
    "update_user_password",
    "create_magic_link",
    "create_access_token",
    "migrate_user_from_external_source",
    "create_org",
    "update_org_metadata",
    "add_user_to_org",
    "delete_user",
    "disable_user",
    "enable_user",
    "allow_org_to_setup_saml_connection",
    "disallow_org_to_setup_saml_connection"
])


def init_base_auth(auth_url: str, api_key: str, token_verification_metadata: TokenVerificationMetadata = None) -> Auth:
    """Fetches metadata required to validate access tokens and returns auth decorators and utilities"""
    auth_url = _validate_url(auth_url)
    token_verification_metadata = _fetch_token_verification_metadata(auth_url, api_key, token_verification_metadata)

    def fetch_user_metadata_by_user_id(user_id, include_orgs=False):
        return _fetch_user_metadata_by_user_id(auth_url, api_key, user_id, include_orgs)

    def fetch_user_metadata_by_email(email, include_orgs=False):
        return _fetch_user_metadata_by_email(auth_url, api_key, email, include_orgs)

    def fetch_user_metadata_by_username(username, include_orgs=False):
        return _fetch_user_metadata_by_username(auth_url, api_key, username, include_orgs)

    def fetch_batch_user_metadata_by_user_ids(user_ids, include_orgs=False):
        return _fetch_batch_user_metadata_by_user_ids(auth_url, api_key, user_ids, include_orgs)

    def fetch_batch_user_metadata_by_emails(emails, include_orgs=False):
        return _fetch_batch_user_metadata_by_emails(auth_url, api_key, emails, include_orgs)

    def fetch_batch_user_metadata_by_usernames(usernames, include_orgs=False):
        return _fetch_batch_user_metadata_by_usernames(auth_url, api_key, usernames, include_orgs)

    def fetch_org(org_id):
        return _fetch_org(auth_url, api_key, org_id)

    def fetch_org_by_query(page_size=10, page_number=0, order_by=OrgQueryOrderBy.CREATED_AT_ASC):
        return _fetch_org_by_query(auth_url, api_key, page_size, page_number, order_by)

    def fetch_users_by_query(page_size=10, page_number=0, order_by=UserQueryOrderBy.CREATED_AT_ASC,
                             email_or_username=None, include_orgs=False):
        return _fetch_users_by_query(auth_url, api_key, page_size, page_number, order_by, email_or_username,
                                     include_orgs)

    def fetch_users_in_org(org_id, page_size=10, page_number=0, include_orgs=False):
        return _fetch_users_in_org(auth_url, api_key, org_id, page_size, page_number, include_orgs)

    def create_user(email, email_confirmed=False, send_email_to_confirm_email_address=True,
                    ask_user_to_update_password_on_login=False,
                    password=None, username=None, first_name=None, last_name=None):
        return _create_user(auth_url, api_key, email, email_confirmed, send_email_to_confirm_email_address,
                            ask_user_to_update_password_on_login,
                            password, username, first_name, last_name)

    def update_user_email(user_id, new_email, require_email_confirmation):
        return _update_user_email(auth_url, api_key, user_id, new_email, require_email_confirmation)

    def update_user_metadata(user_id, username=None, first_name=None, last_name=None, metadata=None):
        return _update_user_metadata(auth_url, api_key, user_id, username, first_name, last_name, metadata)

    def update_user_password(user_id, password, ask_user_to_update_password_on_login=False):
        return _update_user_password(auth_url, api_key, user_id, password, ask_user_to_update_password_on_login)

    def create_magic_link(email, redirect_to_url=None, expires_in_hours=None, create_new_user_if_one_doesnt_exist=None):
        return _create_magic_link(auth_url, api_key, email, redirect_to_url, expires_in_hours,
                                  create_new_user_if_one_doesnt_exist)

    def create_access_token(user_id, duration_in_minutes):
        return _create_access_token(auth_url, api_key, user_id, duration_in_minutes)

    def migrate_user_from_external_source(email, email_confirmed,
                                          existing_user_id=None, existing_password_hash=None,
                                          existing_mfa_base32_encoded_secret=None,
                                          ask_user_to_update_password_on_login=False,
                                          enabled=None, first_name=None, last_name=None, username=None):
        return _migrate_user_from_external_source(auth_url, api_key, email, email_confirmed,
                                                  existing_user_id, existing_password_hash,
                                                  existing_mfa_base32_encoded_secret,
                                                  ask_user_to_update_password_on_login,
                                                  enabled, first_name, last_name, username)

    def create_org(name):
        return _create_org(auth_url, api_key, name)

    def update_org_metadata(org_id, name=None, can_setup_saml=None, metadata=None):
        return _update_org_metadata(auth_url, api_key, org_id, name, can_setup_saml, metadata)

    def add_user_to_org(user_id, org_id, role):
        return _add_user_to_org(auth_url, api_key, user_id, org_id, role)

    def delete_user(user_id):
        return _delete_user(auth_url, api_key, user_id)

    def disable_user(user_id):
        return _disable_user(auth_url, api_key, user_id)

    def enable_user(user_id):
        return _enable_user(auth_url, api_key, user_id)

    def allow_org_to_setup_saml_connection(org_id):
        return _allow_org_to_setup_saml_connection(auth_url, api_key, org_id)

    def disallow_org_to_setup_saml_connection(org_id):
        return _disallow_org_to_setup_saml_connection(auth_url, api_key, org_id)

    validate_access_token_and_get_user = wrap_validate_access_token_and_get_user(token_verification_metadata)

    validate_access_token_and_get_user_with_org = wrap_validate_access_token_and_get_user_with_org(token_verification_metadata)

    validate_access_token_and_get_user_with_org_by_minimum_role = wrap_validate_access_token_and_get_user_with_org_by_minimum_role(
        token_verification_metadata
    )

    validate_access_token_and_get_user_with_org_by_exact_role = wrap_validate_access_token_and_get_user_with_org_by_exact_role(
        token_verification_metadata
    )

    validate_access_token_and_get_user_with_org_by_permission = wrap_validate_access_token_and_get_user_with_org_by_permission(
        token_verification_metadata
    )

    validate_access_token_and_get_user_with_org_by_all_permissions = wrap_validate_access_token_and_get_user_with_org_by_all_permissions(
        token_verification_metadata
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
        fetch_batch_user_metadata_by_user_ids=fetch_batch_user_metadata_by_user_ids,
        fetch_batch_user_metadata_by_emails=fetch_batch_user_metadata_by_emails,
        fetch_batch_user_metadata_by_usernames=fetch_batch_user_metadata_by_usernames,
        fetch_org=fetch_org,
        fetch_org_by_query=fetch_org_by_query,
        fetch_users_by_query=fetch_users_by_query,
        fetch_users_in_org=fetch_users_in_org,
        create_user=create_user,
        update_user_email=update_user_email,
        update_user_metadata=update_user_metadata,
        update_user_password=update_user_password,
        create_magic_link=create_magic_link,
        create_access_token=create_access_token,
        migrate_user_from_external_source=migrate_user_from_external_source,
        create_org=create_org,
        update_org_metadata=update_org_metadata,
        add_user_to_org=add_user_to_org,
        enable_user=enable_user,
        disable_user=disable_user,
        delete_user=delete_user,
        allow_org_to_setup_saml_connection=allow_org_to_setup_saml_connection,
        disallow_org_to_setup_saml_connection=disallow_org_to_setup_saml_connection,
    )
