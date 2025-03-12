import requests
from propelauth_py.api import (
    _ApiKeyAuth,
    _is_valid_hex,
    remove_bearer_if_exists,
    BACKEND_API_BASE_URL,
)
from propelauth_py.errors import (
    EndUserApiKeyException,
    EndUserApiKeyNotFoundException,
    EndUserApiKeyRateLimitedException,
    RateLimitedException,
)
from propelauth_py.types.end_user_api_keys import (
    ApiKeyFull,
    ApiKeyResultPage,
    ApiKeyNew,
    ApiKeyValidation,
)
from propelauth_py.types.user import UserMetadata, OrgFromApiKey
from propelauth_py.user import OrgMemberInfo
from propelauth_py.api import _auth_hostname_header

ENDPOINT_URL = f"{BACKEND_API_BASE_URL}/api/backend/v1/end_user_api_keys"


####################
#       GET        #
####################
def _fetch_api_key(auth_hostname, integration_api_key, api_key_id) -> ApiKeyFull:
    if not _is_valid_hex(api_key_id):
        raise EndUserApiKeyNotFoundException()

    url = f"{ENDPOINT_URL}/{api_key_id}"
    response = requests.get(
        url,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise EndUserApiKeyException(response.json())
    elif response.status_code == 404:
        raise EndUserApiKeyNotFoundException()
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching end user api key")

    json_response = response.json()
    return ApiKeyFull(
        api_key_id=json_response.get("api_key_id"),
        created_at=json_response.get("created_at"),
        expires_at_seconds=json_response.get("expires_at_seconds"),
        metadata=json_response.get("metadata"),
        user_id=json_response.get("user_id"),
        org_id=json_response.get("org_id"),
    )


def _fetch_current_api_keys(
    auth_hostname,
    integration_api_key,
    org_id=None,
    user_id=None,
    user_email=None,
    page_size=None,
    page_number=None,
    api_key_type=None,
) -> ApiKeyResultPage:
    url = ENDPOINT_URL

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
        url,
        auth=_ApiKeyAuth(integration_api_key),
        params=query_params,
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise EndUserApiKeyException(response.json())
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching current end user api keys")

    json_response = response.json()

    api_keys = [
        ApiKeyFull(
            api_key_id=key.get("api_key_id"),
            created_at=key.get("created_at"),
            expires_at_seconds=key.get("expires_at_seconds"),
            metadata=key.get("metadata"),
            user_id=key.get("user_id"),
            org_id=key.get("org_id"),
        )
        for key in json_response.get("api_keys")
    ]

    return ApiKeyResultPage(
        api_keys=api_keys,
        total_api_keys=json_response.get("total_api_keys"),
        current_page=json_response.get("current_page"),
        page_size=json_response.get("page_size"),
        has_more_results=json_response.get("has_more_results"),
    )


def _fetch_archived_api_keys(
    auth_hostname,
    integration_api_key,
    org_id=None,
    user_id=None,
    user_email=None,
    page_size=None,
    page_number=None,
    api_key_type=None,
) -> ApiKeyResultPage:
    url = f"{ENDPOINT_URL}/archived"

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
        url,
        auth=_ApiKeyAuth(integration_api_key),
        params=query_params,
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise EndUserApiKeyException(response.json())
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching archived end user api keys")

    json_response = response.json()

    api_keys = [
        ApiKeyFull(
            api_key_id=key.get("api_key_id"),
            created_at=key.get("created_at"),
            expires_at_seconds=key.get("expires_at_seconds"),
            metadata=key.get("metadata"),
            user_id=key.get("user_id"),
            org_id=key.get("org_id"),
        )
        for key in json_response.get("api_keys")
    ]

    return ApiKeyResultPage(
        api_keys=api_keys,
        total_api_keys=json_response.get("total_api_keys"),
        current_page=json_response.get("current_page"),
        page_size=json_response.get("page_size"),
        has_more_results=json_response.get("has_more_results"),
    )


####################
#       POST       #
####################
def _create_api_key(
    auth_hostname, integration_api_key, org_id, user_id, expires_at_seconds, metadata
) -> ApiKeyNew:
    url = ENDPOINT_URL

    json = {}
    if org_id:
        json["org_id"] = org_id
    if user_id:
        json["user_id"] = user_id
    if expires_at_seconds:
        json["expires_at_seconds"] = expires_at_seconds
    if metadata:
        json["metadata"] = metadata

    response = requests.post(
        url,
        auth=_ApiKeyAuth(integration_api_key),
        json=json,
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise EndUserApiKeyException(response.json())
    elif not response.ok:
        raise RuntimeError("Unknown error when creating end user api key")

    json_response = response.json()
    return ApiKeyNew(
        api_key_id=json_response.get("api_key_id"),
        api_key_token=json_response.get("api_key_token"),
    )


def _validate_api_key(
    auth_hostname, integration_api_key, api_key_token
) -> ApiKeyValidation:
    url = f"{ENDPOINT_URL}/validate"
    json = {"api_key_token": remove_bearer_if_exists(api_key_token)}
    response = requests.post(
        url,
        auth=_ApiKeyAuth(integration_api_key),
        json=json,
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 400:
        raise EndUserApiKeyException(response.json())
    elif response.status_code == 404:
        raise EndUserApiKeyNotFoundException()
    elif response.status_code == 429:
        try:
            end_user_rate_limit_response = response.json()
            raise EndUserApiKeyRateLimitedException(end_user_rate_limit_response)
        except requests.exceptions.JSONDecodeError:
            raise RateLimitedException(response.text)
    elif not response.ok:
        raise RuntimeError("Unknown error when validating end user api key")

    json_response = response.json()

    user = None
    if json_response.get("user") is not None:
        user_data = json_response.get("user")
        user = UserMetadata(
            user_id=user_data.get("user_id"),
            email=user_data.get("email"),
            email_confirmed=user_data.get("email_confirmed"),
            has_password=user_data.get("has_password"),
            username=user_data.get("username"),
            first_name=user_data.get("first_name"),
            last_name=user_data.get("last_name"),
            picture_url=user_data.get("picture_url"),
            locked=user_data.get("locked"),
            enabled=user_data.get("enabled"),
            mfa_enabled=user_data.get("mfa_enabled"),
            can_create_orgs=user_data.get("can_create_orgs"),
            created_at=user_data.get("created_at"),
            last_active_at=user_data.get("last_active_at"),
            org_id_to_org_info=user_data.get("org_id_to_org_info"),
            legacy_org_id=user_data.get("legacy_org_id"),
            impersonator_user_id=user_data.get("impersonator_user_id"),
            metadata=user_data.get("metadata"),
            properties=user_data.get("properties"),
        )

    org = None
    if json_response.get("org") is not None:
        org_data = json_response.get("org")
        org = OrgFromApiKey(
            org_id=org_data.get("org_id"),
            name=org_data.get("org_name"),
            org_name=org_data.get("org_name"),
            max_users=org_data.get("max_users"),
            is_saml_configured=org_data.get("is_saml_configured"),
            legacy_org_id=org_data.get("legacy_org_id"),
            metadata=org_data.get("metadata", {}),
            custom_role_mapping_name=org_data.get("custom_role_mapping_name"),
        )

    user_in_org = None
    if json_response.get("user_in_org") is not None:
        user_in_org_data = json_response.get("user_in_org")
        user_in_org = OrgMemberInfo(
            org_id=user_in_org_data.get("org_id"),
            org_name=user_in_org_data.get("org_name"),
            org_metadata=user_in_org_data.get("org_metadata"),
            user_assigned_role=user_in_org_data.get("user_role"),
            url_safe_org_name=user_in_org_data.get("url_safe_org_name"),
            user_inherited_roles_plus_current_role=user_in_org_data.get(
                "inherited_user_roles_plus_current_role"
            ),
            user_permissions=user_in_org_data.get("user_permissions"),
            org_role_structure=user_in_org_data.get("org_role_structure"),
            assigned_additional_roles=user_in_org_data.get("additional_roles", []),
            legacy_org_id=user_in_org_data.get("legacy_org_id"),
        )

    return ApiKeyValidation(
        metadata=json_response.get("metadata"),
        user=user,
        org=org,
        user_in_org=user_in_org,
    )


####################
#    PUT/PATCH     #
####################
def _update_api_key(
    auth_hostname, integration_api_key, api_key_id, expires_at_seconds, metadata
) -> bool:
    if not _is_valid_hex(api_key_id):
        return False

    url = f"{ENDPOINT_URL}/{api_key_id}"

    json = {}
    if expires_at_seconds:
        json["expires_at_seconds"] = expires_at_seconds
    if metadata:
        json["metadata"] = metadata

    response = requests.patch(
        url,
        auth=_ApiKeyAuth(integration_api_key),
        json=json,
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
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
def _delete_api_key(auth_hostname, integration_api_key, api_key_id) -> bool:
    if not _is_valid_hex(api_key_id):
        return False

    url = f"{ENDPOINT_URL}/{api_key_id}"
    response = requests.delete(
        url,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise EndUserApiKeyException(response.json())
    elif response.status_code == 404:
        raise EndUserApiKeyNotFoundException()
    elif not response.ok:
        raise RuntimeError("Unknown error when deleting end user api key")

    return True
