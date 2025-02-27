from typing import Optional, Dict, Any
import aiohttp

from propelauth_py.api import BadRequestException
from propelauth_py.errors import RateLimitedException


class MigrateUserResponse:
    def __init__(self, user_id: str, email: str, created_user: bool):
        self.user_id = user_id
        self.email = email
        self.created_user = created_user


async def _migrate_user_from_external_source(
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
    picture_url=None,
    properties=None,
    session=None
) -> MigrateUserResponse:
    url = auth_url + "/api/backend/migrate_user"
    json_body = {
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
        "picture_url": picture_url,
        "properties": properties
    }
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_migrate_user_from_external_source(session, url, headers, json_body)
    else:
        return await _do_migrate_user_from_external_source(session, url, headers, json_body)


async def _do_migrate_user_from_external_source(session, url, headers, json_body):
    async with session.post(url, json={k: v for k, v in json_body.items() if v is not None}, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            json_data = await response.json()
            raise BadRequestException(json_data)
        elif not response.ok:
            raise RuntimeError("Unknown error when migrating user")

        json_response = await response.json()
        return MigrateUserResponse(
            user_id=json_response.get('user_id'),
            email=json_response.get('email'),
            created_user=json_response.get('created_user')
        )