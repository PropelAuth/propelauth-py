from collections import namedtuple

from propelauth_py.api import _fetch_token_verification_metadata, _fetch_user_metadata_by_query, \
    _fetch_batch_user_metadata_by_query, TokenVerificationMetadata
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
    "fetch_batch_user_metadata_by_usernames"
])


def init_auth(auth_url: str, api_key: str, token_verification_metadata: TokenVerificationMetadata = None) -> Auth:
    """Fetches metadata required to validate access tokens and returns auth decorators and utilities"""
    auth_url = _validate_url(auth_url)
    token_verification_metadata = _fetch_token_verification_metadata(auth_url, api_key, token_verification_metadata)

    def fetch_user_metadata_by_user_id(user_id):
        return _fetch_user_metadata_by_query(auth_url, api_key, {"user_id": user_id})

    def fetch_user_metadata_by_email(email):
        return _fetch_user_metadata_by_query(auth_url, api_key, {"email": email})

    def fetch_user_metadata_by_username(username):
        return _fetch_user_metadata_by_query(auth_url, api_key, {"username": username})

    def fetch_batch_user_metadata_by_user_ids(user_ids):
        return _fetch_batch_user_metadata_by_query(auth_url, api_key, "user_id", user_ids)

    def fetch_batch_user_metadata_by_emails(emails):
        return _fetch_batch_user_metadata_by_query(auth_url, api_key, "email", emails)

    def fetch_batch_user_metadata_by_usernames(usernames):
        return _fetch_batch_user_metadata_by_query(auth_url, api_key, "username", usernames)

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
    )
