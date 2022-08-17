from collections import namedtuple
from enum import Enum
from uuid import UUID

import requests
from requests.auth import AuthBase

from propelauth_py.errors import CreateUserException, UpdateUserMetadataException, UpdateUserEmailException, \
    BadRequestException

TokenVerificationMetadata = namedtuple("TokenVerificationMetadata", [
    "verifier_key", "issuer"
])


def _fetch_token_verification_metadata(auth_url: str, api_key: str,
                                       token_verification_metadata: TokenVerificationMetadata):
    if token_verification_metadata is not None:
        return token_verification_metadata

    token_verification_metadata_url = auth_url + "/api/v1/token_verification_metadata"
    response = requests.get(token_verification_metadata_url, auth=_ApiKeyAuth(api_key))
    if response.status_code == 401:
        raise ValueError("api_key is incorrect")
    elif response.status_code == 400:
        raise ValueError("Bad request")
    elif response.status_code == 404:
        raise ValueError("auth_url is incorrect")
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching token verification metadata")

    json_response = response.json()
    return TokenVerificationMetadata(
        verifier_key=json_response["verifier_key_pem"],
        issuer=auth_url,
    )


def _fetch_user_metadata_by_user_id(auth_url, api_key, user_id, include_orgs=False):
    if not _is_valid_id(user_id):
        return None

    user_info_url = auth_url + "/api/backend/v1/user/{}".format(user_id)
    query = {"include_orgs": include_orgs}
    return _fetch_user_metadata_by_query(api_key, user_info_url, query)


def _fetch_user_metadata_by_email(auth_url, api_key, email, include_orgs=False):
    user_info_url = auth_url + "/api/backend/v1/user/email"
    query = {"include_orgs": include_orgs, "email": email}
    return _fetch_user_metadata_by_query(api_key, user_info_url, query)


def _fetch_user_metadata_by_username(auth_url, api_key, username, include_orgs=False):
    user_info_url = auth_url + "/api/backend/v1/user/username"
    query = {"include_orgs": include_orgs, "username": username}
    return _fetch_user_metadata_by_query(api_key, user_info_url, query)


def _fetch_user_metadata_by_query(api_key, user_info_url, query):
    response = requests.get(user_info_url, params=_format_params(query), auth=_ApiKeyAuth(api_key))
    if response.status_code == 401:
        raise ValueError("api_key is incorrect")
    elif response.status_code == 400:
        raise ValueError("Bad request: " + response.text)
    elif response.status_code == 404:
        return None
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching user metadata")

    return response.json()


def _fetch_batch_user_metadata_by_user_ids(auth_url, api_key, user_ids, include_orgs):
    user_info_url = auth_url + "/api/backend/v1/user/user_ids"
    params = {"include_orgs": include_orgs}
    body = {"user_ids": user_ids}
    return _fetch_batch_user_metadata_by_query(user_info_url, api_key, params, body, lambda x: x["user_id"])


def _fetch_batch_user_metadata_by_emails(auth_url, api_key, emails, include_orgs):
    user_info_url = auth_url + "/api/backend/v1/user/emails"
    params = {"include_orgs": include_orgs}
    body = {"emails": emails}
    return _fetch_batch_user_metadata_by_query(user_info_url, api_key, params, body, lambda x: x["email"])


def _fetch_batch_user_metadata_by_usernames(auth_url, api_key, usernames, include_orgs):
    user_info_url = auth_url + "/api/backend/v1/user/usernames"
    params = {"include_orgs": include_orgs}
    body = {"usernames": usernames}
    return _fetch_batch_user_metadata_by_query(user_info_url, api_key, params, body, lambda x: x["username"])


def _fetch_batch_user_metadata_by_query(user_info_url, api_key, params, body, key_fn):
    response = requests.post(user_info_url, params=_format_params(params), json=body, auth=_ApiKeyAuth(api_key))
    if response.status_code == 401:
        raise ValueError("api_key is incorrect")
    elif response.status_code == 400:
        raise ValueError("Bad request: " + response.text)
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching batch user metadata")

    json_response = response.json()
    return_value = {}
    for single_item in json_response:
        return_value[key_fn(single_item)] = single_item

    return return_value


def _fetch_org(auth_url, api_key, org_id):
    if not _is_valid_id(org_id):
        return None

    url = auth_url + "/api/backend/v1/org/{}".format(org_id)
    response = requests.get(url, auth=_ApiKeyAuth(api_key))
    if response.status_code == 401:
        raise ValueError("api_key is incorrect")
    elif response.status_code == 404:
        return None
    elif response.status_code == 426:
        raise RuntimeError("Cannot use organizations unless B2B support is enabled. Enable it in your PropelAuth "
                           "dashboard.")
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching org")

    return response.json()


def _fetch_org_by_query(auth_url, api_key, page_size, page_number, order_by):
    url = auth_url + "/api/backend/v1/org/query"
    params = {
        "page_size": page_size,
        "page_number": page_number,
        "order_by": order_by,
    }
    response = requests.get(url, params=_format_params(params), auth=_ApiKeyAuth(api_key))
    if response.status_code == 401:
        raise ValueError("api_key is incorrect")
    elif response.status_code == 400:
        raise ValueError("Bad request: " + response.text)
    elif response.status_code == 426:
        raise RuntimeError("Cannot use organizations unless B2B support is enabled. Enable it in your PropelAuth "
                           "dashboard.")
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching orgs by query")

    return response.json()


def _fetch_users_by_query(auth_url, api_key, page_size, page_number, order_by, email_or_username, include_orgs):
    url = auth_url + "/api/backend/v1/user/query"
    params = {
        "page_size": page_size,
        "page_number": page_number,
        "order_by": order_by,
        "email_or_username": email_or_username,
        "include_orgs": include_orgs,
    }
    response = requests.get(url, params=_format_params(params), auth=_ApiKeyAuth(api_key))
    if response.status_code == 401:
        raise ValueError("api_key is incorrect")
    elif response.status_code == 400:
        raise ValueError("Bad request: " + response.text)
    elif response.status_code == 426:
        raise RuntimeError("Cannot use organizations unless B2B support is enabled. Enable it in your PropelAuth "
                           "dashboard.")
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching orgs by query")

    return response.json()


def _fetch_users_in_org(auth_url, api_key, org_id, page_size, page_number, include_orgs):
    if not _is_valid_id(org_id):
        return {
            "users": [],
            "total_users": 0,
            "current_page": page_number,
            "page_size": page_size,
            "has_more_results": False
        }

    url = auth_url + "/api/backend/v1/user/org/{}".format(org_id)
    params = {
        "page_size": page_size,
        "page_number": page_number,
        "include_orgs": include_orgs,
    }
    response = requests.get(url, params=_format_params(params), auth=_ApiKeyAuth(api_key))
    if response.status_code == 401:
        raise ValueError("api_key is incorrect")
    elif response.status_code == 400:
        raise ValueError("Bad request: " + response.text)
    elif response.status_code == 426:
        raise RuntimeError("Cannot use organizations unless B2B support is enabled. Enable it in your PropelAuth "
                           "dashboard.")
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching users in org")

    return response.json()


def _create_user(auth_url, api_key, email, email_confirmed, send_email_to_confirm_email_address,
                 password, username, first_name, last_name):
    url = auth_url + "/api/backend/v1/user/"
    json = {"email": email, "email_confirmed": email_confirmed,
            "send_email_to_confirm_email_address": send_email_to_confirm_email_address}
    if password is not None:
        json["password"] = password
    if username is not None:
        json["username"] = username
    if first_name is not None:
        json["first_name"] = first_name
    if last_name is not None:
        json["last_name"] = last_name
    response = requests.post(url, json=json, auth=_ApiKeyAuth(api_key))
    if response.status_code == 401:
        raise ValueError("api_key is incorrect")
    elif response.status_code == 400:
        raise CreateUserException(response.json())
    elif not response.ok:
        raise RuntimeError("Unknown error when creating user")

    return response.json()


def _update_user_metadata(auth_url, api_key, user_id, username=None, first_name=None, last_name=None):
    if not _is_valid_id(user_id):
        return False

    url = auth_url + "/api/backend/v1/user/{}".format(user_id)
    json = {}
    if username is not None:
        json["username"] = username
    if first_name is not None:
        json["first_name"] = first_name
    if last_name is not None:
        json["last_name"] = last_name

    response = requests.put(url, json=json, auth=_ApiKeyAuth(api_key))
    if response.status_code == 401:
        raise ValueError("api_key is incorrect")
    elif response.status_code == 400:
        raise UpdateUserMetadataException(response.json())
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when updating metadata")

    return True


def _update_user_email(auth_url, api_key, user_id, new_email, require_email_confirmation):
    if not _is_valid_id(user_id):
        return False

    url = auth_url + "/api/backend/v1/user/{}/email".format(user_id)
    json = {
        "new_email": new_email,
        "require_email_confirmation": require_email_confirmation,
    }

    response = requests.put(url, json=json, auth=_ApiKeyAuth(api_key))
    if response.status_code == 401:
        raise ValueError("api_key is incorrect")
    elif response.status_code == 400:
        raise UpdateUserEmailException(response.json())
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when updating user email")

    return True


def _create_magic_link(auth_url, api_key, email,
                       redirect_to_url=None, expires_in_hours=None, create_new_user_if_one_doesnt_exist=None):
    url = auth_url + "/api/backend/v1/magic_link"
    json = {"email": email}
    if redirect_to_url is not None:
        json["redirect_to_url"] = redirect_to_url
    if expires_in_hours is not None:
        json["expires_in_hours"] = expires_in_hours
    if create_new_user_if_one_doesnt_exist is not None:
        json["create_new_user_if_one_doesnt_exist"] = create_new_user_if_one_doesnt_exist

    response = requests.post(url, json=json, auth=_ApiKeyAuth(api_key))
    if response.status_code == 401:
        raise ValueError("api_key is incorrect")
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif not response.ok:
        raise RuntimeError("Unknown error when creating magic link")

    return response.json()


def _migrate_user_from_external_source(auth_url, api_key, email, email_confirmed,
                                       existing_user_id=None, existing_password_hash=None,
                                       existing_mfa_base32_encoded_secret=None,
                                       enabled=None, first_name=None, last_name=None, username=None):
    url = auth_url + "/api/backend/v1/migrate_user/"
    json = {
        "email": email,
        "email_confirmed": email_confirmed,
        "existing_user_id": existing_user_id,
        "existing_password_hash": existing_password_hash,
        "existing_mfa_base32_encoded_secret": existing_mfa_base32_encoded_secret,
        "enabled": enabled,
        "first_name": first_name,
        "last_name": last_name,
        "username": username
    }

    response = requests.post(url, json=json, auth=_ApiKeyAuth(api_key))
    if response.status_code == 401:
        raise ValueError("api_key is incorrect")
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif not response.ok:
        raise RuntimeError("Unknown error when migrating user")

    return response.json()


def _create_org(auth_url, api_key, name):
    url = auth_url + "/api/backend/v1/org/"
    json = {"name": name}

    response = requests.post(url, json=json, auth=_ApiKeyAuth(api_key))
    if response.status_code == 401:
        raise ValueError("api_key is incorrect")
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif not response.ok:
        raise RuntimeError("Unknown error when creating an org")

    return response.json()


def _add_user_to_org(auth_url, api_key, user_id, org_id, role):
    url = auth_url + "/api/backend/v1/org/add_user"
    json = {"user_id": user_id, "org_id": org_id, "role": role}

    response = requests.post(url, json=json, auth=_ApiKeyAuth(api_key))
    if response.status_code == 401:
        raise ValueError("api_key is incorrect")
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when adding a user to the org")

    return True


class OrgQueryOrderBy(str, Enum):
    CREATED_AT_ASC = "CREATED_AT_ASC"
    CREATED_AT_DESC = "CREATED_AT_DESC"
    NAME = "NAME"


class UserQueryOrderBy(str, Enum):
    CREATED_AT_ASC = "CREATED_AT_ASC"
    CREATED_AT_DESC = "CREATED_AT_DESC"
    LAST_ACTIVE_AT_ASC = "LAST_ACTIVE_AT_ASC"
    LAST_ACTIVE_AT_DESC = "LAST_ACTIVE_AT_DESC"
    EMAIL = "EMAIL"
    USERNAME = "USERNAME"


class _ApiKeyAuth(AuthBase):
    """Attaches API Key Authentication to the given Request object."""

    def __init__(self, api_key):
        self.api_key = api_key

    def __call__(self, r):
        r.headers["Authorization"] = "Bearer " + self.api_key
        return r


def _format_params(params):
    return {key: _format_param(value) for key, value in params.items() if value is not None}


def _format_param(param):
    if type(param) == bool:
        if param:
            return "true"
        else:
            return "false"
    else:
        return param


def _is_valid_id(identifier):
    try:
        uuid_obj = UUID(identifier, version=4)
        return str(uuid_obj) == identifier
    except ValueError:
        return False
