from typing import Optional
import aiohttp

from propelauth_py.api import ENDPOINT_PATH, UserNotFoundException, BadRequestException
from propelauth_py.errors import RateLimitedException


class CreateAccessTokenResponse:
    def __init__(self, access_token: str):
        self.access_token = access_token


async def _create_access_token(auth_url, integration_api_key, user_id, duration_in_minutes, session=None) -> CreateAccessTokenResponse:
    from propelauth_py.async_api.user import _is_valid_id
    if not _is_valid_id(user_id):
        raise UserNotFoundException()

    url = auth_url + "/api/access_token"
    json_body = {"user_id": user_id, "duration_in_minutes": duration_in_minutes}
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_create_access_token(session, url, headers, json_body)
    else:
        return await _do_create_access_token(session, url, headers, json_body)


async def _do_create_access_token(session, url, headers, json_body):
    async with session.post(url, json=json_body, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            json_data = await response.json()
            raise BadRequestException(json_data)
        elif response.status == 403:
            raise UserNotFoundException()
        elif response.status == 404:
            raise RuntimeError("Access token creation is not enabled")
        elif not response.ok:
            raise RuntimeError("Unknown error when creating access token")

        json_response = await response.json()
        return CreateAccessTokenResponse(
            access_token=json_response.get('access_token')
        )