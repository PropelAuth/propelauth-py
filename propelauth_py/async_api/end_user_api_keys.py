from typing import Optional, Dict, Any, List
import aiohttp

from propelauth_py.api import ENDPOINT_PATH, UserNotFoundException, BadRequestException
from propelauth_py.errors import RateLimitedException, EndUserApiKeyException, EndUserApiKeyRateLimitedException
from propelauth_py.types.end_user_api_keys import ApiKeyResponse, ApiKeyMetadataResponse


async def _fetch_api_key(auth_url, integration_api_key, api_key_id, session=None) -> Optional[ApiKeyMetadataResponse]:
    from propelauth_py.async_api.user import _is_valid_id, _is_valid_hex
    if not _is_valid_id(api_key_id) and not _is_valid_hex(api_key_id):
        return None

    url = auth_url + f"/api/backend/api_key/{api_key_id}"
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_fetch_api_key(session, url, headers)
    else:
        return await _do_fetch_api_key(session, url, headers)


async def _do_fetch_api_key(session, url, headers):
    async with session.get(url, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            text = await response.text()
            raise ValueError("Bad request: " + text)
        elif response.status == 404:
            return None
        elif not response.ok:
            raise RuntimeError("Unknown error when fetching API key")

        json_response = await response.json()
        return ApiKeyMetadataResponse.from_json(json_response)


async def _fetch_current_api_keys(
    auth_url,
    integration_api_key,
    org_id=None,
    user_id=None,
    user_email=None,
    page_size=None,
    page_number=None,
    api_key_type=None,
    session=None
):
    url = auth_url + "/api/backend/api_key/current"
    query = {
        "org_id": org_id,
        "user_id": user_id,
        "user_email": user_email,
        "page_size": page_size,
        "page_number": page_number,
        "api_key_type": api_key_type,
    }
    
    return await _fetch_api_keys(auth_url, integration_api_key, url, query, session)


async def _fetch_archived_api_keys(
    auth_url,
    integration_api_key,
    org_id=None,
    user_id=None,
    user_email=None,
    page_size=None,
    page_number=None,
    api_key_type=None,
    session=None
):
    url = auth_url + "/api/backend/api_key/archived"
    query = {
        "org_id": org_id,
        "user_id": user_id,
        "user_email": user_email,
        "page_size": page_size,
        "page_number": page_number,
        "api_key_type": api_key_type,
    }
    
    return await _fetch_api_keys(auth_url, integration_api_key, url, query, session)


async def _fetch_api_keys(auth_url, integration_api_key, url, query, session=None):
    from propelauth_py.async_api.user import _format_params
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_fetch_api_keys(session, url, headers, query)
    else:
        return await _do_fetch_api_keys(session, url, headers, query)


async def _do_fetch_api_keys(session, url, headers, query):
    async with session.get(url, params=query, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            text = await response.text()
            raise ValueError("Bad request: " + text)
        elif not response.ok:
            raise RuntimeError("Unknown error when fetching API keys")

        json_response = await response.json()
        api_keys = json_response.get('api_keys', [])
        count = json_response.get('count', 0)
        
        return {
            "api_keys": [ApiKeyMetadataResponse.from_json(api_key) for api_key in api_keys],
            "count": count
        }


async def _create_api_key(
    auth_url,
    integration_api_key,
    org_id=None,
    user_id=None,
    expires_at_seconds=None,
    metadata=None,
    session=None
) -> ApiKeyResponse:
    from propelauth_py.async_api.user import _is_valid_id

    if org_id is not None and not _is_valid_id(org_id):
        raise ValueError("Invalid org_id format")
    if user_id is not None and not _is_valid_id(user_id):
        raise UserNotFoundException()
    if org_id is None and user_id is None:
        raise ValueError("Either org_id or user_id must be provided")
    if org_id is not None and user_id is not None:
        raise ValueError("Cannot specify both org_id and user_id")

    url = auth_url + "/api/backend/api_key"
    json_body = {
        "org_id": org_id,
        "user_id": user_id,
        "expires_at_seconds": expires_at_seconds,
        "metadata": metadata
    }
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_create_api_key(session, url, headers, json_body)
    else:
        return await _do_create_api_key(session, url, headers, json_body)


async def _do_create_api_key(session, url, headers, json_body):
    async with session.post(url, json={k: v for k, v in json_body.items() if v is not None}, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            json_data = await response.json()
            raise BadRequestException(json_data)
        elif response.status == 404:
            if json_body.get("org_id") is not None:
                raise ValueError("Org not found")
            else:
                raise UserNotFoundException()
        elif not response.ok:
            raise RuntimeError("Unknown error when creating API key")

        json_response = await response.json()
        return ApiKeyResponse(
            api_key_id=json_response.get('api_key_id'),
            api_key=json_response.get('api_key'),
            metadata=json_response.get('metadata')
        )


async def _update_api_key(
    auth_url,
    integration_api_key,
    api_key_id,
    expires_at_seconds=None,
    metadata=None,
    session=None
):
    from propelauth_py.async_api.user import _is_valid_id, _is_valid_hex
    if not _is_valid_id(api_key_id) and not _is_valid_hex(api_key_id):
        raise ValueError("Invalid api_key_id format")

    url = auth_url + f"/api/backend/api_key/{api_key_id}"
    json_body = {
        "expires_at_seconds": expires_at_seconds,
        "metadata": metadata
    }
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_update_api_key(session, url, headers, json_body)
    else:
        return await _do_update_api_key(session, url, headers, json_body)


async def _do_update_api_key(session, url, headers, json_body):
    async with session.put(url, json={k: v for k, v in json_body.items() if v is not None}, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            json_data = await response.json()
            raise BadRequestException(json_data)
        elif response.status == 404:
            raise ValueError("API key not found")
        elif not response.ok:
            raise RuntimeError("Unknown error when updating API key")

        return True


async def _delete_api_key(auth_url, integration_api_key, api_key_id, session=None):
    from propelauth_py.async_api.user import _is_valid_id, _is_valid_hex
    if not _is_valid_id(api_key_id) and not _is_valid_hex(api_key_id):
        raise ValueError("Invalid api_key_id format")

    url = auth_url + f"/api/backend/api_key/{api_key_id}"
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_delete_api_key(session, url, headers)
    else:
        return await _do_delete_api_key(session, url, headers)


async def _do_delete_api_key(session, url, headers):
    async with session.delete(url, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            text = await response.text()
            raise ValueError("Bad request: " + text)
        elif response.status == 404:
            raise ValueError("API key not found")
        elif not response.ok:
            raise RuntimeError("Unknown error when deleting API key")

        return True


async def _validate_api_key(auth_url, integration_api_key, api_key_token, session=None):
    url = auth_url + "/api/backend/api_key/validate"
    json_body = {"api_key_token": api_key_token}
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_validate_api_key(session, url, headers, json_body)
    else:
        return await _do_validate_api_key(session, url, headers, json_body)


async def _do_validate_api_key(session, url, headers, json_body):
    async with session.post(url, json=json_body, headers=headers) as response:
        if response.status == 401:
            return None
        elif response.status == 429:
            text = await response.text()
            try:
                error_json = await response.json()
                if error_json.get("rate_limit_for") == "end_user_api_key":
                    raise EndUserApiKeyRateLimitedException(text)
            except Exception:
                # If it's not JSON or doesn't have the right structure, treat as regular rate limit
                pass
            raise RateLimitedException(text)
        elif response.status == 400:
            try:
                error_json = await response.json()
                if error_json.get("type") == "end_user_api_key_error":
                    raise EndUserApiKeyException(error_json.get("message"))
            except EndUserApiKeyException:
                raise
            except Exception:
                # If it's not JSON or doesn't have the right structure, treat as regular bad request
                pass
            
            text = await response.text()
            raise ValueError("Bad request: " + text)
        elif not response.ok:
            raise RuntimeError("Unknown error when validating API key")

        json_response = await response.json()
        return {
            "user_id": json_response.get('user_id'),
            "org_id": json_response.get('org_id'),
            "org_name": json_response.get('org_name'),
            "api_key_id": json_response.get('api_key_id'),
            "api_key_metadata": json_response.get('api_key_metadata'),
        }