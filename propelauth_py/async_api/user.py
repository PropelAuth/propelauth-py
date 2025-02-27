from typing import Optional, Any, Dict, List
import aiohttp
from uuid import UUID

from propelauth_py.api import ENDPOINT_PATH, UserNotFoundException, BadRequestException
from propelauth_py.types.user import UserMetadata
from propelauth_py.errors import RateLimitedException


# Helper functions
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


async def _fetch_user_metadata_by_query(integration_api_key, user_info_url, query, session) -> Optional[UserMetadata]:
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_fetch_user_metadata_by_query(session, user_info_url, headers, query)
    else:
        return await _do_fetch_user_metadata_by_query(session, user_info_url, headers, query)


async def _do_fetch_user_metadata_by_query(session, user_info_url, headers, query):
    async with session.get(user_info_url, params=_format_params(query), headers=headers) as response:
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
            raise RuntimeError("Unknown error when fetching user metadata")

        json_response = await response.json()

        return UserMetadata(
            user_id=json_response.get('user_id'),
            email=json_response.get('email'),
            email_confirmed=json_response.get('email_confirmed'),
            has_password=json_response.get('has_password'),
            username=json_response.get('username'),
            first_name=json_response.get('first_name'),
            last_name=json_response.get('last_name'),
            picture_url=json_response.get('picture_url'),
            locked=json_response.get('locked'),
            enabled=json_response.get('enabled'),
            mfa_enabled=json_response.get('mfa_enabled'),
            can_create_orgs=json_response.get('can_create_orgs'),
            created_at=json_response.get('created_at'),
            last_active_at=json_response.get('last_active_at'),
            org_id_to_org_info=json_response.get('org_id_to_org_info'),
            legacy_org_id=json_response.get('legacy_org_id'),
            impersonator_user_id=json_response.get('impersonator_user_id'),
            metadata=json_response.get('metadata'),
            properties=json_response.get('properties')
        )


async def _fetch_user_metadata_by_user_id(
    auth_url, integration_api_key, user_id, include_orgs=False, session=None
) -> Optional[UserMetadata]:
    if not _is_valid_id(user_id):
        return None

    user_info_url = auth_url + f"{ENDPOINT_PATH}/{user_id}"
    query = {"include_orgs": include_orgs}
    return await _fetch_user_metadata_by_query(integration_api_key, user_info_url, query, session)


async def _fetch_user_metadata_by_email(
    auth_url, integration_api_key, email, include_orgs=False, session=None
) -> Optional[UserMetadata]:
    user_info_url = auth_url + f"{ENDPOINT_PATH}/email"
    query = {"email": email, "include_orgs": include_orgs}
    return await _fetch_user_metadata_by_query(integration_api_key, user_info_url, query, session)


async def _fetch_user_metadata_by_username(
    auth_url, integration_api_key, username, include_orgs=False, session=None
) -> Optional[UserMetadata]:
    user_info_url = auth_url + f"{ENDPOINT_PATH}/username"
    query = {"username": username, "include_orgs": include_orgs}
    return await _fetch_user_metadata_by_query(integration_api_key, user_info_url, query, session)


async def _fetch_user_signup_query_params_by_user_id(
    auth_url, integration_api_key, user_id, session=None
) -> Dict[str, str]:
    if not _is_valid_id(user_id):
        raise UserNotFoundException()

    user_info_url = auth_url + f"{ENDPOINT_PATH}/{user_id}/signup_query_params"
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_fetch_user_signup_query_params(session, user_info_url, headers)
    else:
        return await _do_fetch_user_signup_query_params(session, user_info_url, headers)


async def _do_fetch_user_signup_query_params(session, user_info_url, headers):
    async with session.get(user_info_url, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            text = await response.text()
            raise ValueError("Bad request: " + text)
        elif response.status == 404:
            raise UserNotFoundException()
        elif not response.ok:
            raise RuntimeError("Unknown error when fetching user signup query params")

        json_response = await response.json()
        return json_response.get('user_signup_query_params', {})


async def _fetch_batch_user_metadata_by_user_ids(
    auth_url, integration_api_key, user_ids, include_orgs=False, session=None
):
    batch_url = auth_url + f"{ENDPOINT_PATH}/batch"
    json_body = {"user_ids": user_ids, "include_orgs": include_orgs}
    return await _fetch_batch_user_metadata(integration_api_key, batch_url, json_body, session)


async def _fetch_batch_user_metadata_by_emails(
    auth_url, integration_api_key, emails, include_orgs=False, session=None
):
    batch_url = auth_url + f"{ENDPOINT_PATH}/batch_by_email"
    json_body = {"emails": emails, "include_orgs": include_orgs}
    return await _fetch_batch_user_metadata(integration_api_key, batch_url, json_body, session)


async def _fetch_batch_user_metadata_by_usernames(
    auth_url, integration_api_key, usernames, include_orgs=False, session=None
):
    batch_url = auth_url + f"{ENDPOINT_PATH}/batch_by_username"
    json_body = {"usernames": usernames, "include_orgs": include_orgs}
    return await _fetch_batch_user_metadata(integration_api_key, batch_url, json_body, session)


async def _fetch_batch_user_metadata(integration_api_key, batch_url, json_body, session=None):
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_fetch_batch_user_metadata(session, batch_url, headers, json_body)
    else:
        return await _do_fetch_batch_user_metadata(session, batch_url, headers, json_body)


async def _do_fetch_batch_user_metadata(session, batch_url, headers, json_body):
    async with session.post(batch_url, json=json_body, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            text = await response.text()
            raise ValueError("Bad request: " + text)
        elif not response.ok:
            raise RuntimeError("Unknown error when fetching batch user metadata")

        json_response = await response.json()
        users = json_response.get('users', [])
        
        return [
            UserMetadata(
                user_id=user.get('user_id'),
                email=user.get('email'),
                email_confirmed=user.get('email_confirmed'),
                has_password=user.get('has_password'),
                username=user.get('username'),
                first_name=user.get('first_name'),
                last_name=user.get('last_name'),
                picture_url=user.get('picture_url'),
                locked=user.get('locked'),
                enabled=user.get('enabled'),
                mfa_enabled=user.get('mfa_enabled'),
                can_create_orgs=user.get('can_create_orgs'),
                created_at=user.get('created_at'),
                last_active_at=user.get('last_active_at'),
                org_id_to_org_info=user.get('org_id_to_org_info'),
                legacy_org_id=user.get('legacy_org_id'),
                metadata=user.get('metadata'),
                properties=user.get('properties')
            )
            for user in users
        ]


async def _fetch_users_by_query(
    auth_url,
    integration_api_key,
    page_size=10,
    page_number=0,
    order_by=None,
    email_or_username=None,
    include_orgs=False,
    legacy_user_id=None,
    session=None
):
    url = auth_url + f"{ENDPOINT_PATH}/query"
    json_body = {
        "page_size": page_size,
        "page_number": page_number,
        "order_by": order_by.value if order_by else None,
        "email_or_username": email_or_username,
        "include_orgs": include_orgs,
        "legacy_user_id": legacy_user_id,
    }
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_fetch_users_by_query(session, url, headers, json_body)
    else:
        return await _do_fetch_users_by_query(session, url, headers, json_body)


async def _do_fetch_users_by_query(session, url, headers, json_body):
    async with session.post(url, json=json_body, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            text = await response.text()
            raise ValueError("Bad request: " + text)
        elif not response.ok:
            raise RuntimeError("Unknown error when fetching users by query")

        json_response = await response.json()
        total_users = json_response.get('total_users', 0)
        current_page = json_response.get('current_page', 0)
        page_size = json_response.get('page_size', 0)
        has_more_results = json_response.get('has_more_results', False)
        users = json_response.get('users', [])

        return {
            "total_users": total_users,
            "current_page": current_page,
            "page_size": page_size,
            "has_more_results": has_more_results,
            "users": [
                UserMetadata(
                    user_id=user.get('user_id'),
                    email=user.get('email'),
                    email_confirmed=user.get('email_confirmed'),
                    has_password=user.get('has_password'),
                    username=user.get('username'),
                    first_name=user.get('first_name'),
                    last_name=user.get('last_name'),
                    picture_url=user.get('picture_url'),
                    locked=user.get('locked'),
                    enabled=user.get('enabled'),
                    mfa_enabled=user.get('mfa_enabled'),
                    can_create_orgs=user.get('can_create_orgs'),
                    created_at=user.get('created_at'),
                    last_active_at=user.get('last_active_at'),
                    org_id_to_org_info=user.get('org_id_to_org_info'),
                    legacy_org_id=user.get('legacy_org_id'),
                    metadata=user.get('metadata'),
                    properties=user.get('properties')
                )
                for user in users
            ]
        }


async def _fetch_users_in_org(
    auth_url,
    integration_api_key,
    org_id,
    page_size=10,
    page_number=0,
    include_orgs=False,
    role=None,
    session=None
):
    if not _is_valid_id(org_id):
        raise ValueError("Invalid org_id format")

    url = auth_url + f"{ENDPOINT_PATH}/org/{org_id}"
    query = {
        "page_size": page_size,
        "page_number": page_number,
        "include_orgs": include_orgs,
        "role": role,
    }
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_fetch_users_in_org(session, url, headers, query)
    else:
        return await _do_fetch_users_in_org(session, url, headers, query)


async def _do_fetch_users_in_org(session, url, headers, query):
    async with session.get(url, params=_format_params(query), headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            text = await response.text()
            raise ValueError("Bad request: " + text)
        elif response.status == 404:
            raise ValueError("Org not found")
        elif not response.ok:
            raise RuntimeError("Unknown error when fetching users in org")

        json_response = await response.json()
        total_users = json_response.get('total_users', 0)
        current_page = json_response.get('current_page', 0)
        page_size = json_response.get('page_size', 0)
        has_more_results = json_response.get('has_more_results', False)
        users = json_response.get('users', [])

        return {
            "total_users": total_users,
            "current_page": current_page,
            "page_size": page_size,
            "has_more_results": has_more_results,
            "users": [
                UserMetadata(
                    user_id=user.get('user_id'),
                    email=user.get('email'),
                    email_confirmed=user.get('email_confirmed'),
                    has_password=user.get('has_password'),
                    username=user.get('username'),
                    first_name=user.get('first_name'),
                    last_name=user.get('last_name'),
                    picture_url=user.get('picture_url'),
                    locked=user.get('locked'),
                    enabled=user.get('enabled'),
                    mfa_enabled=user.get('mfa_enabled'),
                    can_create_orgs=user.get('can_create_orgs'),
                    created_at=user.get('created_at'),
                    last_active_at=user.get('last_active_at'),
                    org_id_to_org_info=user.get('org_id_to_org_info'),
                    legacy_org_id=user.get('legacy_org_id'),
                    metadata=user.get('metadata'),
                    properties=user.get('properties')
                )
                for user in users
            ]
        }


async def _create_user(
    auth_url,
    integration_api_key,
    email,
    email_confirmed=False,
    send_email_to_confirm_email_address=True,
    ask_user_to_update_password_on_login=False,
    password=None,
    username=None,
    first_name=None,
    last_name=None,
    properties=None,
    ignore_domain_restrictions=False,
    session=None
):
    url = auth_url + f"{ENDPOINT_PATH}"
    json_body = {
        "email": email,
        "email_confirmed": email_confirmed,
        "send_email_to_confirm_email_address": send_email_to_confirm_email_address,
        "ask_user_to_update_password_on_login": ask_user_to_update_password_on_login,
        "password": password,
        "username": username,
        "first_name": first_name,
        "last_name": last_name,
        "properties": properties,
        "ignore_domain_restrictions": ignore_domain_restrictions
    }
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_create_user(session, url, headers, json_body)
    else:
        return await _do_create_user(session, url, headers, json_body)


async def _do_create_user(session, url, headers, json_body):
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
            raise RuntimeError("Unknown error when creating user")

        json_response = await response.json()
        return {
            "user_id": json_response.get('user_id'),
            "email": json_response.get('email'),
            "username": json_response.get('username'),
            "properties": json_response.get('properties'),
        }


async def _invite_user_to_org(
    auth_url,
    integration_api_key,
    email,
    org_id,
    role,
    additional_roles=[],
    session=None
):
    if not _is_valid_id(org_id):
        raise ValueError("Invalid org_id format")

    url = auth_url + f"/api/orgs/{org_id}/invites"
    json_body = {
        "email": email,
        "role": role,
        "additional_roles": additional_roles
    }
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_invite_user_to_org(session, url, headers, json_body)
    else:
        return await _do_invite_user_to_org(session, url, headers, json_body)


async def _do_invite_user_to_org(session, url, headers, json_body):
    async with session.post(url, json=json_body, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            json_data = await response.json()
            raise BadRequestException(json_data)
        elif response.status == 404:
            raise ValueError("Org not found")
        elif not response.ok:
            raise RuntimeError("Unknown error when inviting user to org")

        json_response = await response.json()
        return {
            "org_id": json_response.get('org_id'),
            "email": json_response.get('email'),
            "role": json_response.get('role'),
            "additional_roles": json_response.get('additional_roles', []),
        }


async def _resend_email_confirmation(auth_url, integration_api_key, user_id, session=None):
    if not _is_valid_id(user_id):
        raise UserNotFoundException()

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}/resend_email_confirmation"
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_resend_email_confirmation(session, url, headers)
    else:
        return await _do_resend_email_confirmation(session, url, headers)


async def _do_resend_email_confirmation(session, url, headers):
    async with session.post(url, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            text = await response.text()
            raise ValueError("Bad request: " + text)
        elif response.status == 404:
            raise UserNotFoundException()
        elif not response.ok:
            raise RuntimeError("Unknown error when resending email confirmation")

        return True


async def _logout_all_user_sessions(auth_url, integration_api_key, user_id, session=None):
    if not _is_valid_id(user_id):
        raise UserNotFoundException()

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}/logout"
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_logout_all_user_sessions(session, url, headers)
    else:
        return await _do_logout_all_user_sessions(session, url, headers)


async def _do_logout_all_user_sessions(session, url, headers):
    async with session.post(url, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            text = await response.text()
            raise ValueError("Bad request: " + text)
        elif response.status == 404:
            raise UserNotFoundException()
        elif not response.ok:
            raise RuntimeError("Unknown error when logging out all user sessions")

        return True


async def _update_user_email(
    auth_url,
    integration_api_key,
    user_id,
    new_email,
    require_email_confirmation,
    session=None
):
    if not _is_valid_id(user_id):
        raise UserNotFoundException()

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}/email"
    json_body = {
        "new_email": new_email,
        "require_email_confirmation": require_email_confirmation
    }
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_update_user_email(session, url, headers, json_body)
    else:
        return await _do_update_user_email(session, url, headers, json_body)


async def _do_update_user_email(session, url, headers, json_body):
    async with session.put(url, json=json_body, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            json_data = await response.json()
            raise BadRequestException(json_data)
        elif response.status == 404:
            raise UserNotFoundException()
        elif not response.ok:
            raise RuntimeError("Unknown error when updating user email")

        return True


async def _update_user_metadata(
    auth_url,
    integration_api_key,
    user_id,
    username=None,
    first_name=None,
    last_name=None,
    metadata=None,
    properties=None,
    picture_url=None,
    update_password_required=None,
    session=None
):
    if not _is_valid_id(user_id):
        raise UserNotFoundException()

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}"
    json_body = {
        "username": username,
        "first_name": first_name,
        "last_name": last_name,
        "metadata": metadata,
        "properties": properties,
        "picture_url": picture_url,
        "update_password_required": update_password_required
    }
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_update_user_metadata(session, url, headers, json_body)
    else:
        return await _do_update_user_metadata(session, url, headers, json_body)


async def _do_update_user_metadata(session, url, headers, json_body):
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
            raise UserNotFoundException()
        elif not response.ok:
            raise RuntimeError("Unknown error when updating user metadata")

        return True


async def _clear_user_password(auth_url, integration_api_key, user_id, session=None):
    if not _is_valid_id(user_id):
        raise UserNotFoundException()

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}/password"
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_clear_user_password(session, url, headers)
    else:
        return await _do_clear_user_password(session, url, headers)


async def _do_clear_user_password(session, url, headers):
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
            raise UserNotFoundException()
        elif not response.ok:
            raise RuntimeError("Unknown error when clearing user password")

        return True


async def _update_user_password(
    auth_url,
    integration_api_key,
    user_id,
    password,
    ask_user_to_update_password_on_login=False,
    session=None
):
    if not _is_valid_id(user_id):
        raise UserNotFoundException()

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}/password"
    json_body = {
        "password": password,
        "ask_user_to_update_password_on_login": ask_user_to_update_password_on_login
    }
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_update_user_password(session, url, headers, json_body)
    else:
        return await _do_update_user_password(session, url, headers, json_body)


async def _do_update_user_password(session, url, headers, json_body):
    async with session.put(url, json=json_body, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            json_data = await response.json()
            raise BadRequestException(json_data)
        elif response.status == 404:
            raise UserNotFoundException()
        elif not response.ok:
            raise RuntimeError("Unknown error when updating user password")

        return True


async def _delete_user(auth_url, integration_api_key, user_id, session=None):
    if not _is_valid_id(user_id):
        raise UserNotFoundException()

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}"
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_delete_user(session, url, headers)
    else:
        return await _do_delete_user(session, url, headers)


async def _do_delete_user(session, url, headers):
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
            raise UserNotFoundException()
        elif not response.ok:
            raise RuntimeError("Unknown error when deleting user")

        return True


async def _disable_user(auth_url, integration_api_key, user_id, session=None):
    if not _is_valid_id(user_id):
        raise UserNotFoundException()

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}/disable"
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_disable_user(session, url, headers)
    else:
        return await _do_disable_user(session, url, headers)


async def _do_disable_user(session, url, headers):
    async with session.post(url, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            text = await response.text()
            raise ValueError("Bad request: " + text)
        elif response.status == 404:
            raise UserNotFoundException()
        elif not response.ok:
            raise RuntimeError("Unknown error when disabling user")

        return True


async def _enable_user(auth_url, integration_api_key, user_id, session=None):
    if not _is_valid_id(user_id):
        raise UserNotFoundException()

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}/enable"
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_enable_user(session, url, headers)
    else:
        return await _do_enable_user(session, url, headers)


async def _do_enable_user(session, url, headers):
    async with session.post(url, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            text = await response.text()
            raise ValueError("Bad request: " + text)
        elif response.status == 404:
            raise UserNotFoundException()
        elif not response.ok:
            raise RuntimeError("Unknown error when enabling user")

        return True


async def _disable_user_2fa(auth_url, integration_api_key, user_id, session=None):
    if not _is_valid_id(user_id):
        raise UserNotFoundException()

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}/disable_2fa"
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_disable_user_2fa(session, url, headers)
    else:
        return await _do_disable_user_2fa(session, url, headers)


async def _do_disable_user_2fa(session, url, headers):
    async with session.post(url, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            text = await response.text()
            raise ValueError("Bad request: " + text)
        elif response.status == 404:
            raise UserNotFoundException()
        elif not response.ok:
            raise RuntimeError("Unknown error when disabling user 2FA")

        return True


async def _enable_user_can_create_orgs(auth_url, integration_api_key, user_id, session=None):
    if not _is_valid_id(user_id):
        raise UserNotFoundException()

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}/can_create_orgs/enable"
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_enable_user_can_create_orgs(session, url, headers)
    else:
        return await _do_enable_user_can_create_orgs(session, url, headers)


async def _do_enable_user_can_create_orgs(session, url, headers):
    async with session.post(url, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            text = await response.text()
            raise ValueError("Bad request: " + text)
        elif response.status == 404:
            raise UserNotFoundException()
        elif not response.ok:
            raise RuntimeError("Unknown error when enabling user can create orgs")

        return True


async def _disable_user_can_create_orgs(auth_url, integration_api_key, user_id, session=None):
    if not _is_valid_id(user_id):
        raise UserNotFoundException()

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}/can_create_orgs/disable"
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_disable_user_can_create_orgs(session, url, headers)
    else:
        return await _do_disable_user_can_create_orgs(session, url, headers)


async def _do_disable_user_can_create_orgs(session, url, headers):
    async with session.post(url, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            text = await response.text()
            raise ValueError("Bad request: " + text)
        elif response.status == 404:
            raise UserNotFoundException()
        elif not response.ok:
            raise RuntimeError("Unknown error when disabling user can create orgs")

        return True


async def _validate_personal_api_key(auth_url, integration_api_key, api_key_token, session=None):
    url = auth_url + "/api/backend/user_api_key/validate_api_key"
    json_body = {"api_key_token": api_key_token}
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_validate_personal_api_key(session, url, headers, json_body)
    else:
        return await _do_validate_personal_api_key(session, url, headers, json_body)


async def _do_validate_personal_api_key(session, url, headers, json_body):
    async with session.post(url, json=json_body, headers=headers) as response:
        if response.status == 401:
            return None
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            text = await response.text()
            raise ValueError("Bad request: " + text)
        elif not response.ok:
            raise RuntimeError("Unknown error when validating personal API key")

        json_response = await response.json()
        return {
            "user_id": json_response.get('user_id'),
            "org_id": json_response.get('org_id')
        }