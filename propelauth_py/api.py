from collections import namedtuple
from enum import Enum
from uuid import UUID

import requests
from requests.auth import AuthBase

from propelauth_py.errors import (
    BadRequestException,
    UserNotFoundException,
    EndUserApiKeyException,
    EndUserApiKeyNotFoundException,
)


def _migrate_user_from_external_source(
    auth_url,
    integration_api_key,
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
    url = auth_url + "/api/backend/v1/migrate_user/"
    json = {
        "email": email,
        "email_confirmed": email_confirmed,
        "existing_user_id": existing_user_id,
        "existing_password_hash": existing_password_hash,
        "existing_mfa_base32_encoded_secret": existing_mfa_base32_encoded_secret,
        "ask_user_to_update_password_on_login": ask_user_to_update_password_on_login,
        "enabled": enabled,
        "first_name": first_name,
        "last_name": last_name,
        "username": username,
        "properties": properties,
    }

    response = requests.post(url, json=json, auth=_ApiKeyAuth(integration_api_key))
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif not response.ok:
        raise RuntimeError("Unknown error when migrating user")

    return response.json()


def _fetch_api_key(auth_url, integration_api_key, api_key_id):
    if not _is_valid_hex(api_key_id):
        return False

    url = auth_url + "/api/backend/v1/end_user_api_keys/{}".format(api_key_id)
    response = requests.get(url, auth=_ApiKeyAuth(integration_api_key))

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 400:
        raise EndUserApiKeyException(response.json())
    elif response.status_code == 404:
        raise EndUserApiKeyNotFoundException()
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching end user api key")

    return response.json()


def _fetch_current_api_keys(
    auth_url, integration_api_key, org_id, user_id, user_email, page_size, page_number
):
    url = auth_url + "/api/backend/v1/end_user_api_keys"

    query_params = {}
    if org_id:
        query_params["org_id"] = org_id
    if user_id:
        query_params["user_id"] = user_id
    if user_email:
        query_params["user_email"] = user_email
    if page_size:
        query_params["page_size"] = page_size
    if page_number:
        query_params["page_number"] = page_number

    response = requests.get(
        url, auth=_ApiKeyAuth(integration_api_key), params=query_params
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 400:
        raise EndUserApiKeyException(response.json())
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching current end user api keys")

    return response.json()


def _fetch_archived_api_keys(
    auth_url, integration_api_key, org_id, user_id, user_email, page_size, page_number
):
    url = auth_url + "/api/backend/v1/end_user_api_keys/archived"

    query_params = {}
    if org_id:
        query_params["org_id"] = org_id
    if user_id:
        query_params["user_id"] = user_id
    if user_email:
        query_params["user_email"] = user_email
    if page_size:
        query_params["page_size"] = page_size
    if page_number:
        query_params["page_number"] = page_number

    response = requests.get(
        url, auth=_ApiKeyAuth(integration_api_key), params=query_params
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 400:
        raise EndUserApiKeyException(response.json())
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching archived end user api keys")

    return response.json()


def _create_api_key(
    auth_url, integration_api_key, org_id, user_id, expires_at_seconds, metadata
):
    url = auth_url + "/api/backend/v1/end_user_api_keys"

    json = {}
    if org_id:
        json["org_id"] = org_id
    if user_id:
        json["user_id"] = user_id
    if expires_at_seconds:
        json["expires_at_seconds"] = expires_at_seconds
    if metadata:
        json["metadata"] = metadata

    response = requests.post(url, auth=_ApiKeyAuth(integration_api_key), json=json)

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 400:
        raise EndUserApiKeyException(response.json())
    elif not response.ok:
        raise RuntimeError("Unknown error when creating end user api key")

    return response.json()


def _update_api_key(
    auth_url, integration_api_key, api_key_id, expires_at_seconds, metadata
):
    if not _is_valid_hex(api_key_id):
        return False

    url = auth_url + "/api/backend/v1/end_user_api_keys/{}".format(api_key_id)

    json = {}
    if expires_at_seconds:
        json["expires_at_seconds"] = expires_at_seconds
    if metadata:
        json["metadata"] = metadata

    response = requests.patch(url, auth=_ApiKeyAuth(integration_api_key), json=json)

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 400:
        raise EndUserApiKeyException(response.json())
    elif response.status_code == 404:
        raise EndUserApiKeyNotFoundException()
    elif not response.ok:
        raise RuntimeError("Unknown error when updating end user api key")

    return True


def _delete_api_key(auth_url, integration_api_key, api_key_id):
    if not _is_valid_hex(api_key_id):
        return False

    url = auth_url + "/api/backend/v1/end_user_api_keys/{}".format(api_key_id)
    response = requests.delete(url, auth=_ApiKeyAuth(integration_api_key))

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 400:
        raise EndUserApiKeyException(response.json())
    elif response.status_code == 404:
        raise EndUserApiKeyNotFoundException()
    elif not response.ok:
        raise RuntimeError("Unknown error when deleting end user api key")

    return True


def _validate_personal_api_key(auth_url, integration_api_key, api_key_token):
    api_key_validation = _validate_api_key(auth_url, integration_api_key, api_key_token)
    if not api_key_validation["user"] or api_key_validation["org"]:
        raise EndUserApiKeyException({"api_key_token": ["Not a personal API Key"]})
    return {
        "user": api_key_validation["user"],
        "metadata": api_key_validation["metadata"],
    }


def _validate_org_api_key(auth_url, integration_api_key, api_key_token):
    api_key_validation = _validate_api_key(auth_url, integration_api_key, api_key_token)
    if not api_key_validation["org"]:
        raise EndUserApiKeyException({"api_key_token": ["Not an org API Key"]})
    return {
        "org": api_key_validation["org"],
        "metadata": api_key_validation["metadata"],
        "user": api_key_validation["user"],
        "user_in_org": api_key_validation["user_in_org"],
    }


def _validate_api_key(auth_url, integration_api_key, api_key_token):
    url = auth_url + "/api/backend/v1/end_user_api_keys/validate"
    json = {"api_key_token": remove_bearer_if_exists(api_key_token)}
    response = requests.post(url, auth=_ApiKeyAuth(integration_api_key), json=json)

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 400:
        raise EndUserApiKeyException(response.json())
    elif response.status_code == 404:
        raise EndUserApiKeyNotFoundException()
    elif not response.ok:
        raise RuntimeError("Unknown error when validating end user api key")

    return response.json()


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

    def __init__(self, integration_api_key):
        self.integration_api_key = integration_api_key

    def __call__(self, r):
        r.headers["Authorization"] = "Bearer " + self.integration_api_key
        return r


def remove_bearer_if_exists(token: str) -> str:
    if not token:
        return token
    elif token.lower().startswith("bearer "):
        return token[7:]
    else:
        return token


def _format_params(params):
    return {
        key: _format_param(value) for key, value in params.items() if value is not None
    }


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


def _is_valid_hex(identifier):
    try:
        int(identifier, 16)
        return True
    except ValueError:
        return False
