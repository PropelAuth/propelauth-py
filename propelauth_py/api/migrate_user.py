import requests
import httpx
from propelauth_py.api import _ApiKeyAuth, _auth_hostname_header, BACKEND_API_BASE_URL, _is_valid_id, _get_async_headers
from propelauth_py.errors import BadRequestException, RateLimitedException
from propelauth_py.types.user import CreatedUser

ENDPOINT_URL = f"{BACKEND_API_BASE_URL}/api/backend/v1/migrate_user"


def _migrate_user_from_external_source(
    auth_hostname,
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
    picture_url=None,
    properties=None,
) -> CreatedUser:
    url = ENDPOINT_URL + "/"
    json = {
        "email": email,
        "email_confirmed": email_confirmed,
        "existing_user_id": existing_user_id,
        "existing_password_hash": existing_password_hash,
        "existing_mfa_base32_encoded_secret": existing_mfa_base32_encoded_secret,
        "update_password_required": ask_user_to_update_password_on_login,
        "enabled": enabled,
        "first_name": first_name,
        "last_name": last_name,
        "username": username,
        "picture_url": picture_url,
    }
    if properties is not None:
        json["properties"] = properties

    response = requests.post(
        url,
        json=json,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif not response.ok:
        raise RuntimeError("Unknown error when migrating user")

    json_response = response.json()
    return CreatedUser(
        user_id=json_response.get('user_id')
    )
    
async def _migrate_user_from_external_source_async(
    httpx_client: httpx.AsyncClient,
    auth_hostname,
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
    picture_url=None,
    properties=None,
) -> CreatedUser:
    url = ENDPOINT_URL + "/"
    json_body = {
        "email": email,
        "email_confirmed": email_confirmed,
        "existing_user_id": existing_user_id,
        "existing_password_hash": existing_password_hash,
        "existing_mfa_base32_encoded_secret": existing_mfa_base32_encoded_secret,
        "update_password_required": ask_user_to_update_password_on_login,
        "enabled": enabled,
        "first_name": first_name,
        "last_name": last_name,
        "username": username,
        "picture_url": picture_url,
    }
    if properties is not None:
        json_body["properties"] = properties

    response = await httpx_client.post(
        url=url,
        json=json_body,
        headers=_get_async_headers(auth_hostname=auth_hostname, integration_api_key=integration_api_key)
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise BadRequestException(response.json())
        
    response.raise_for_status()
    json_response = response.json()
    return CreatedUser(
        user_id=json_response.get('user_id')
    )
    
def _migrate_user_password(
    auth_hostname,
    integration_api_key,
    user_id,
    password_hash,
) -> bool:
    if not _is_valid_id(user_id):
        return False
    
    url = ENDPOINT_URL + "/password"
    
    json = {
        "user_id": user_id,
        "password_hash": password_hash
    }
  
    response = requests.post(
        url,
        json=json,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif not response.ok:
        raise RuntimeError("Unknown error when migrating user password")

    return True

async def _migrate_user_password_async(
    httpx_client: httpx.AsyncClient,
    auth_hostname,
    integration_api_key,
    user_id,
    password_hash,
) -> bool:
    if not _is_valid_id(user_id):
        return False
    
    url = ENDPOINT_URL + "/password"
    
    json_body = {
        "user_id": user_id,
        "password_hash": password_hash
    }
  
    response = await httpx_client.post(
        url=url,
        json=json_body,
        headers=_get_async_headers(auth_hostname=auth_hostname, integration_api_key=integration_api_key)
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise BadRequestException(response.json())
        
    response.raise_for_status()
    return True
