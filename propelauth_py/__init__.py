from collections import namedtuple

from propelauth_py.api import _fetch_token_verification_metadata, TokenVerificationMetadata, \
    _fetch_user_metadata_by_user_id, \
    _fetch_user_metadata_by_email, _fetch_user_metadata_by_username, _fetch_batch_user_metadata_by_user_ids, \
    _fetch_batch_user_metadata_by_emails, _fetch_batch_user_metadata_by_usernames, OrgQueryOrderBy, UserQueryOrderBy, \
    _fetch_org, _fetch_org_by_query, _fetch_users_by_query, _fetch_users_in_org, _create_user, _update_user_email, \
    _update_user_metadata, _create_magic_link, _migrate_user_from_external_source, _create_org, _add_user_to_org
from propelauth_py.auth_fns import wrap_validate_access_token_and_get_user, \
    wrap_validate_access_token_and_get_user_with_org, validate_org_access_and_get_org
from propelauth_py.errors import UnauthorizedException
from propelauth_py.validation import _validate_url

Auth = namedtuple("Auth", [
    "validate_access_token_and_get_user", "validate_access_token_and_get_user_with_org",
    "validate_org_access_and_get_org",
    "fetch_user_metadata_by_user_id", "fetch_user_metadata_by_email", "fetch_user_metadata_by_username",
    "fetch_batch_user_metadata_by_user_ids",
    "fetch_batch_user_metadata_by_emails",
    "fetch_batch_user_metadata_by_usernames",
    "fetch_org", "fetch_org_by_query", "fetch_users_by_query", "fetch_users_in_org",
    "create_user",
    "update_user_email",
    "update_user_metadata",
    "create_magic_link", "migrate_user_from_external_source", "create_org", "add_user_to_org"
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
                    password=None, username=None, first_name=None, last_name=None):
        return _create_user(auth_url, api_key, email, email_confirmed, send_email_to_confirm_email_address,
                            password, username, first_name, last_name)

    def update_user_email(user_id, new_email, require_email_confirmation):
        return _update_user_email(auth_url, api_key, user_id, new_email, require_email_confirmation)

    def update_user_metadata(user_id, username=None, first_name=None, last_name=None):
        return _update_user_metadata(auth_url, api_key, user_id, username, first_name, last_name)

    def create_magic_link(email, redirect_to_url=None, expires_in_hours=None, create_new_user_if_one_doesnt_exist=None):
        return _create_magic_link(auth_url, api_key, email, redirect_to_url, expires_in_hours,
                                  create_new_user_if_one_doesnt_exist)

    def migrate_user_from_external_source(email, email_confirmed,
                                          existing_user_id=None, existing_password_hash=None,
                                          existing_mfa_base32_encoded_secret=None,
                                          enabled=None, first_name=None, last_name=None, username=None):
        return _migrate_user_from_external_source(auth_url, api_key, email, email_confirmed,
                                                  existing_user_id, existing_password_hash,
                                                  existing_mfa_base32_encoded_secret,
                                                  enabled, first_name, last_name, username)

    def create_org(name):
        return _create_org(auth_url, api_key, name)

    def add_user_to_org(user_id, org_id, role):
        return _add_user_to_org(auth_url, api_key, user_id, org_id, role)

    validate_access_token_and_get_user = wrap_validate_access_token_and_get_user(token_verification_metadata)
    validate_access_token_and_get_user_with_org = wrap_validate_access_token_and_get_user_with_org(
        token_verification_metadata
    )
    return Auth(
        validate_access_token_and_get_user=validate_access_token_and_get_user,
        validate_access_token_and_get_user_with_org=validate_access_token_and_get_user_with_org,
        validate_org_access_and_get_org=validate_org_access_and_get_org,
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
        create_magic_link=create_magic_link,
        migrate_user_from_external_source=migrate_user_from_external_source,
        create_org=create_org,
        add_user_to_org=add_user_to_org,
    )
