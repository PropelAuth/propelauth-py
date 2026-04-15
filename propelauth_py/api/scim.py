from typing import Optional

import httpx
import requests

from propelauth_py.api import (
    BACKEND_API_BASE_URL,
    _ApiKeyAuth,
    _auth_hostname_header,
    _format_params,
    _get_async_headers,
    _is_valid_id,
)
from propelauth_py.api.end_user_api_keys import (
    _validate_api_key,
    _validate_api_key_async,
)
from propelauth_py.errors import (
    BadRequestException,
    EndUserApiKeyException,
    RateLimitedException,
    UpdateUserMetadataException,
)
from propelauth_py.types.scim import (
    FetchOrgScimGroupsRequest,
    ScimGroup,
    ScimGroupMember,
    ScimGroupResult,
    ScimGroupResultPage,
)

SCIM_ENDPOINT_URL = f"{BACKEND_API_BASE_URL}/api/backend/v1/scim"


####################
#       GET        #
####################
def _fetch_org_scim_groups(
    auth_hostname,
    integration_api_key,
    org_id,
    user_id=None,
    page_size=10,
    page_number=0,
) -> ScimGroupResultPage:
    url = f"{SCIM_ENDPOINT_URL}/{org_id}/groups"
    params = {"page_size": page_size, "page_number": page_number, "user_id": user_id}

    response = requests.get(
        url,
        params=_format_params(params),
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 404:
        raise RuntimeError("Organization not found")
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching org SCIM groups")

    json_response = response.json()

    groups = [
        ScimGroupResult(
            group_id=key.get("group_id"),
            display_name=key.get("display_name"),
            externalIdFromIdp=key.get("external_id_from_idp"),
        )
        for key in json_response.get("groups")
    ]

    return ScimGroupResultPage(
        groups=groups,
        page_number=json_response.get("page_number"),
        page_size=json_response.get("page_size"),
        total_groups=json_response.get("total_groups"),
    )


async def _fetch_org_scim_groups_async(
    httpx_client: httpx.AsyncClient,
    auth_hostname,
    integration_api_key,
    org_id,
    user_id=None,
    page_size=10,
    page_number=0,
) -> ScimGroupResultPage:

    url = f"{SCIM_ENDPOINT_URL}/{org_id}/groups"
    
    params = {
        "page_number": page_number,
        "page_size": page_size,
        "user_id": user_id,
    }
    formatted_params = _format_params(params)

    response = await httpx_client.get(
        url=url,
        params=formatted_params,
        headers=_get_async_headers(
            auth_hostname=auth_hostname, integration_api_key=integration_api_key
        ),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 404:
        raise RuntimeError("Organization not found")

    response.raise_for_status()
    json_response = response.json()

    groups = [
        ScimGroupResult(
            group_id=key.get("group_id"),
            display_name=key.get("display_name"),
            externalIdFromIdp=key.get("external_id_from_idp"),
        )
        for key in json_response.get("groups")
    ]

    return ScimGroupResultPage(
        groups=groups,
        page_number=json_response.get("page_number"),
        page_size=json_response.get("page_size"),
        total_groups=json_response.get("total_groups"),
    )

def _fetch_scim_group(
    auth_hostname,
    integration_api_key,
    org_id,
    group_id
) -> ScimGroup:
    url = f"{SCIM_ENDPOINT_URL}/{org_id}/groups/{group_id}"

    response = requests.get(
        url,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 404:
        raise RuntimeError("Organization not found")
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching SCIM group")

    json_response = response.json()

    members = [
        ScimGroupMember(
            user_id=key.get("user_id"),
        )
        for key in json_response.get("members")
    ]

    return ScimGroup(
        members=members,
        display_name=json_response.get("display_name"),
        externalIdFromIdp=json_response.get("external_id_from_idp"),
        group_id=json_response.get("group_id"),
    )

async def _fetch_scim_group_async(
    httpx_client: httpx.AsyncClient,
    auth_hostname,
    integration_api_key,
    org_id,
    group_id,
) -> ScimGroup:

    url = f"{SCIM_ENDPOINT_URL}/{org_id}/groups/{group_id}"

    response = await httpx_client.get(
        url=url,
        headers=_get_async_headers(
            auth_hostname=auth_hostname, integration_api_key=integration_api_key
        ),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 404:
        raise RuntimeError("Organization not found")

    response.raise_for_status()
    json_response = response.json()

    members = [
        ScimGroupMember(
            user_id=key.get("user_id"),
        )
        for key in json_response.get("members")
    ]
    
    return ScimGroup(
        members=members,
        display_name=json_response.get("display_name"),
        externalIdFromIdp=json_response.get("external_id_from_idp"),
        group_id=json_response.get("group_id"),
    )
