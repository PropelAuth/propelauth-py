import requests
from propelauth_py.api import _ApiKeyAuth, _is_valid_hex, remove_bearer_if_exists
from propelauth_py.errors import EndUserApiKeyException, EndUserApiKeyNotFoundException

ENDPOINT_PATH = "/api/backend/v1/end_user_api_keys"


####################
#       GET        #
####################
def _fetch_api_key(auth_url, integration_api_key, api_key_id):
    if not _is_valid_hex(api_key_id):
        return False

    url = auth_url + f"{ENDPOINT_PATH}/{api_key_id}"
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
    auth_url,
    integration_api_key,
    org_id=None,
    user_id=None,
    user_email=None,
    page_size=None,
    page_number=None,
    api_key_type=None,
):
    url = auth_url + ENDPOINT_PATH

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
    if api_key_type:
        query_params["api_key_type"] = api_key_type

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
    auth_url,
    integration_api_key,
    org_id=None,
    user_id=None,
    user_email=None,
    page_size=None,
    page_number=None,
    api_key_type=None,
):
    url = auth_url + f"{ENDPOINT_PATH}/archived"

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
    if api_key_type:
        query_params["api_key_type"] = api_key_type

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


####################
#       POST       #
####################
def _create_api_key(
    auth_url, integration_api_key, org_id, user_id, expires_at_seconds, metadata
):
    url = auth_url + ENDPOINT_PATH

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


def _validate_api_key(auth_url, integration_api_key, api_key_token):
    url = auth_url + f"{ENDPOINT_PATH}/validate"
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


####################
#    PUT/PATCH     #
####################
def _update_api_key(
    auth_url, integration_api_key, api_key_id, expires_at_seconds, metadata
):
    if not _is_valid_hex(api_key_id):
        return False

    url = auth_url + f"{ENDPOINT_PATH}/{api_key_id}"

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


####################
#      DELETE      #
####################
def _delete_api_key(auth_url, integration_api_key, api_key_id):
    if not _is_valid_hex(api_key_id):
        return False

    url = auth_url + f"{ENDPOINT_PATH}/{api_key_id}"
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
