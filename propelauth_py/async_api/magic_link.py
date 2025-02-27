from typing import Optional, Dict, Any
import aiohttp

from propelauth_py.api import BadRequestException
from propelauth_py.errors import RateLimitedException


class CreateMagicLinkResponse:
    def __init__(self, magic_link: str, email: str, user_id: Optional[str] = None, created_user: bool = False):
        self.magic_link = magic_link
        self.email = email
        self.user_id = user_id
        self.created_user = created_user


async def _create_magic_link(
    auth_url, 
    integration_api_key, 
    email, 
    redirect_to_url=None, 
    expires_in_hours=None, 
    create_new_user_if_one_doesnt_exist=None, 
    user_signup_query_parameters=None,
    session=None
) -> CreateMagicLinkResponse:
    url = auth_url + "/api/backend/magic_link"
    json_body = {
        "email": email,
        "redirect_to_url": redirect_to_url,
        "expires_in_hours": expires_in_hours,
        "create_new_user_if_one_doesnt_exist": create_new_user_if_one_doesnt_exist,
        "user_signup_query_parameters": user_signup_query_parameters
    }
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_create_magic_link(session, url, headers, json_body)
    else:
        return await _do_create_magic_link(session, url, headers, json_body)


async def _do_create_magic_link(session, url, headers, json_body):
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
            raise RuntimeError("Unknown error when creating magic link")

        json_response = await response.json()
        return CreateMagicLinkResponse(
            magic_link=json_response.get('magic_link'),
            email=json_response.get('email'),
            user_id=json_response.get('user_id'),
            created_user=json_response.get('created_user', False)
        )