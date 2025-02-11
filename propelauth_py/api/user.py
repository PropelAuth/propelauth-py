from typing import Optional, Dict
import requests

from propelauth_py.api import _ApiKeyAuth, _format_params, _is_valid_id
from propelauth_py.api.end_user_api_keys import _validate_api_key
from propelauth_py.types.user import UserMetadata, UsersPagedResponse, CreatedUser, PersonalApiKeyValidation, UserSignupQueryParams
from propelauth_py.errors import (
    CreateUserException,
    EndUserApiKeyException,
    InviteUserToOrgException,
    UpdateUserEmailException,
    UpdateUserMetadataException,
    UpdateUserPasswordException,
    RateLimitedException,
)

ENDPOINT_PATH = "/api/backend/v1/user"


####################
#       GET        #
####################
def _fetch_user_metadata_by_user_id(
    auth_url, integration_api_key, user_id, include_orgs=False
) -> Optional[UserMetadata]:
    if not _is_valid_id(user_id):
        return None

    user_info_url = auth_url + f"{ENDPOINT_PATH}/{user_id}"
    query = {"include_orgs": include_orgs}
    return _fetch_user_metadata_by_query(integration_api_key, user_info_url, query)


def _fetch_user_signup_query_params_by_user_id(
    auth_url,
    integration_api_key,
    user_id,
) -> Optional[UserSignupQueryParams]:
    if not _is_valid_id(user_id):
        return None

    user_signup_query_params_url = (
        auth_url + f"{ENDPOINT_PATH}/{user_id}/signup_query_parameters"
    )
    response = requests.get(
        url=user_signup_query_params_url, auth=_ApiKeyAuth(integration_api_key)
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 404:
        return None
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching user signup query params")

    json_response = response.json()
    return UserSignupQueryParams(
        user_signup_query_parameters=json_response.get('user_signup_query_parameters')
    )


def _fetch_user_metadata_by_email(
    auth_url, integration_api_key, email, include_orgs=False
) -> Optional[UserMetadata]:
    user_info_url = auth_url + f"{ENDPOINT_PATH}/email"
    query = {"include_orgs": include_orgs, "email": email}
    return _fetch_user_metadata_by_query(integration_api_key, user_info_url, query)


def _fetch_user_metadata_by_username(
    auth_url, integration_api_key, username, include_orgs=False
) -> Optional[UserMetadata]:
    user_info_url = auth_url + f"{ENDPOINT_PATH}/username"
    query = {"include_orgs": include_orgs, "username": username}
    return _fetch_user_metadata_by_query(integration_api_key, user_info_url, query)


def _fetch_user_metadata_by_query(integration_api_key, user_info_url, query) -> Optional[UserMetadata]:
    response = requests.get(
        user_info_url,
        params=_format_params(query),
        auth=_ApiKeyAuth(integration_api_key),
    )
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise ValueError("Bad request: " + response.text)
    elif response.status_code == 404:
        return None
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching user metadata")

    json_response = response.json()

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


def _fetch_batch_user_metadata_by_user_ids(
    auth_url, integration_api_key, user_ids, include_orgs
) -> Dict[str, UserMetadata]:
    user_info_url = auth_url + f"{ENDPOINT_PATH}/user_ids"
    params = {"include_orgs": include_orgs}
    body = {"user_ids": user_ids}
    return _fetch_batch_user_metadata_by_query(
        user_info_url, integration_api_key, params, body, lambda x: x["user_id"]
    )


def _fetch_batch_user_metadata_by_emails(
    auth_url, integration_api_key, emails, include_orgs
) -> Dict[str, UserMetadata]:
    user_info_url = auth_url + f"{ENDPOINT_PATH}/emails"
    params = {"include_orgs": include_orgs}
    body = {"emails": emails}
    return _fetch_batch_user_metadata_by_query(
        user_info_url, integration_api_key, params, body, lambda x: x["email"]
    )


def _fetch_batch_user_metadata_by_usernames(
    auth_url, integration_api_key, usernames, include_orgs
) -> Dict[str, UserMetadata]:
    user_info_url = auth_url + f"{ENDPOINT_PATH}/usernames"
    params = {"include_orgs": include_orgs}
    body = {"usernames": usernames}
    return _fetch_batch_user_metadata_by_query(
        user_info_url, integration_api_key, params, body, lambda x: x["username"]
    )


def _fetch_batch_user_metadata_by_query(
    user_info_url, integration_api_key, params, body, key_fn
) -> Dict[str, UserMetadata]:
    response = requests.post(
        user_info_url,
        params=_format_params(params),
        json=body,
        auth=_ApiKeyAuth(integration_api_key),
    )
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise ValueError("Bad request: " + response.text)
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching batch user metadata")

    json_response = response.json()
    return_value = {}
    for single_item in json_response:
        return_value[key_fn(single_item)] = single_item

    return return_value


def _fetch_users_by_query(
    auth_url,
    integration_api_key,
    page_size,
    page_number,
    order_by,
    email_or_username,
    include_orgs,
    legacy_user_id,
) -> UsersPagedResponse:
    url = auth_url + f"{ENDPOINT_PATH}/query"
    params = {
        "page_size": page_size,
        "page_number": page_number,
        "order_by": order_by,
        "email_or_username": email_or_username,
        "include_orgs": include_orgs,
        "legacy_user_id": legacy_user_id,
    }
    response = requests.get(
        url, params=_format_params(params), auth=_ApiKeyAuth(integration_api_key)
    )
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise ValueError("Bad request: " + response.text)
    elif response.status_code == 426:
        raise RuntimeError(
            "Cannot use organizations unless B2B support is enabled. Enable it in your PropelAuth "
            "dashboard."
        )
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching orgs by query")

    json_response = response.json()
    
    users = [
        UserMetadata(
            user_id=key.get('user_id'),
            email=key.get('email'),
            email_confirmed=key.get('email_confirmed'),
            has_password=key.get('has_password'),
            username=key.get('username'),
            first_name=key.get('first_name'),
            last_name=key.get('last_name'),
            picture_url=key.get('picture_url'),
            locked=key.get('locked'),
            enabled=key.get('enabled'),
            mfa_enabled=key.get('mfa_enabled'),
            can_create_orgs=key.get('can_create_orgs'),
            created_at=key.get('created_at'),
            last_active_at=key.get('last_active_at'),
            org_id_to_org_info=key.get('org_id_to_org_info'),
            legacy_org_id=key.get('legacy_org_id'),
            impersonator_user_id=key.get('impersonator_user_id'),
            metadata=key.get('metadata'),
            properties=key.get('properties')
        )
        for key in json_response.get('users')
    ]
    
    return UsersPagedResponse(
        users=users,
        total_users=json_response.get('total_users'),
        current_page=json_response.get('current_page'),
        page_size=json_response.get('page_size'),
        has_more_results=json_response.get('has_more_results')
    )


def _fetch_users_in_org(
    auth_url, integration_api_key, org_id, page_size, page_number, include_orgs, role
) -> UsersPagedResponse:
    if not _is_valid_id(org_id):
        return UsersPagedResponse(
            users=[],
            total_users=0,
            current_page=page_number,
            page_size=page_size,
            has_more_results=False,
        )

    url = auth_url + f"{ENDPOINT_PATH}/org/{org_id}"
    params = {
        "page_size": page_size,
        "page_number": page_number,
        "include_orgs": include_orgs,
        "role": role,
    }
    response = requests.get(
        url, params=_format_params(params), auth=_ApiKeyAuth(integration_api_key)
    )
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise ValueError("Bad request: " + response.text)
    elif response.status_code == 426:
        raise RuntimeError(
            "Cannot use organizations unless B2B support is enabled. Enable it in your PropelAuth "
            "dashboard."
        )
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching users in org")

    json_response = response.json()
    
    users = [
        UserMetadata(
            user_id=key.get('user_id'),
            email=key.get('email'),
            email_confirmed=key.get('email_confirmed'),
            has_password=key.get('has_password'),
            username=key.get('username'),
            first_name=key.get('first_name'),
            last_name=key.get('last_name'),
            picture_url=key.get('picture_url'),
            locked=key.get('locked'),
            enabled=key.get('enabled'),
            mfa_enabled=key.get('mfa_enabled'),
            can_create_orgs=key.get('can_create_orgs'),
            created_at=key.get('created_at'),
            last_active_at=key.get('last_active_at'),
            org_id_to_org_info=key.get('org_id_to_org_info'),
            legacy_org_id=key.get('legacy_org_id'),
            impersonator_user_id=key.get('impersonator_user_id'),
            metadata=key.get('metadata'),
            properties=key.get('properties')
        )
        for key in json_response.get('users')
    ]
    
    return UsersPagedResponse(
        users=users,
        total_users=json_response.get('total_users'),
        current_page=json_response.get('current_page'),
        page_size=json_response.get('page_size'),
        has_more_results=json_response.get('has_more_results')
    )


####################
#       POST     #
####################
def _create_user(
    auth_url,
    integration_api_key,
    email,
    email_confirmed,
    send_email_to_confirm_email_address,
    ask_user_to_update_password_on_login,
    password,
    username,
    first_name,
    last_name,
    properties,
    ignore_domain_restrictions
) -> CreatedUser:
    url = auth_url + f"{ENDPOINT_PATH}/"
    json = {
        "email": email,
        "email_confirmed": email_confirmed,
        "send_email_to_confirm_email_address": send_email_to_confirm_email_address,
        "ask_user_to_update_password_on_login": ask_user_to_update_password_on_login,
    }
    if password is not None:
        json["password"] = password
    if username is not None:
        json["username"] = username
    if first_name is not None:
        json["first_name"] = first_name
    if last_name is not None:
        json["last_name"] = last_name
    if properties is not None:
        json["properties"] = properties
    if ignore_domain_restrictions is not None:
        json["ignore_domain_restrictions"] = ignore_domain_restrictions
    response = requests.post(url, json=json, auth=_ApiKeyAuth(integration_api_key))
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise CreateUserException(response.json())
    elif not response.ok:
        raise RuntimeError("Unknown error when creating user")

    json_response = response.json()
    return CreatedUser(
        user_id=json_response.get('user_id')
    )


def _disable_user(auth_url, integration_api_key, user_id) -> bool:
    if not _is_valid_id(user_id):
        return False

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}/disable"
    response = requests.post(url, auth=_ApiKeyAuth(integration_api_key))
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when disabling user")

    return True


def _enable_user(auth_url, integration_api_key, user_id) -> bool:
    if not _is_valid_id(user_id):
        return False

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}/enable"
    response = requests.post(url, auth=_ApiKeyAuth(integration_api_key))
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when enabling user")

    return True


def _disable_user_2fa(auth_url, integration_api_key, user_id) -> bool:
    if not _is_valid_id(user_id):
        return False

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}/disable_2fa"
    response = requests.post(url, auth=_ApiKeyAuth(integration_api_key))

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when enabling user")

    return True


def _invite_user_to_org(
    auth_url, integration_api_key, email, org_id, role, additional_roles=[]
) -> bool:
    if not _is_valid_id(org_id):
        return False

    endpoint_path = "/api/backend/v1/invite_user"
    url = auth_url + endpoint_path
    json = {
        "email": email,
        "org_id": org_id,
        "role": role,
        "additional_roles": additional_roles,
    }
    response = requests.post(url, json=json, auth=_ApiKeyAuth(integration_api_key))

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        try:
            response_json = response.json()
            raise InviteUserToOrgException(response_json)
        except requests.exceptions.JSONDecodeError:
            raise ValueError("Bad request: " + response.text)
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when updating metadata")

    return True


def _resend_email_confirmation(auth_url, integration_api_key, user_id) -> bool:
    if not _is_valid_id(user_id):
        return False

    endpoint_path = "/api/backend/v1/resend_email_confirmation"
    url = auth_url + endpoint_path
    json = {
        "user_id": user_id,
    }
    response = requests.post(url, json=json, auth=_ApiKeyAuth(integration_api_key))

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 404:
        return False
    elif response.status_code == 429:
        try:
            # Check if this is specifically an email-send rate limit error
            error_message = response.json()["user_facing_error"]
            raise RateLimitedException(error_message)
        except requests.exceptions.JSONDecodeError:
            raise RateLimitedException(response.text)
    elif response.status_code == 400:
        if response.json().get("user_facing_error"):
            raise ValueError(response.json().get("user_facing_error"))
        else:
            raise RuntimeError("Unknown error when resending email confirmation")
    elif not response.ok:
        raise RuntimeError("Unknown error when resending email confirmation")

    return True


def _logout_all_user_sessions(auth_url, integration_api_key, user_id) -> bool:
    if not _is_valid_id(user_id):
        return False

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}/logout_all_sessions"
    response = requests.post(url, auth=_ApiKeyAuth(integration_api_key))

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when logging out all user sessions")

    return True


####################
#     PATCH/PUT    #
####################
def _update_user_metadata(
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
)-> bool:
    if not _is_valid_id(user_id):
        return False

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}"
    json = {}
    if username is not None:
        json["username"] = username
    if first_name is not None:
        json["first_name"] = first_name
    if last_name is not None:
        json["last_name"] = last_name
    if metadata is not None:
        json["metadata"] = metadata
    if properties is not None:
        json["properties"] = properties
    if picture_url is not None:
        json["picture_url"] = picture_url
    if update_password_required is not None:
        json["update_password_required"] = update_password_required

    response = requests.put(url, json=json, auth=_ApiKeyAuth(integration_api_key))
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise UpdateUserMetadataException(response.json())
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when updating metadata")

    return True


def _update_user_password(
    auth_url,
    integration_api_key,
    user_id,
    password,
    ask_user_to_update_password_on_login,
) -> bool:
    if not _is_valid_id(user_id):
        return False

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}/password"
    json = {"password": password}
    if ask_user_to_update_password_on_login is not None:
        json["ask_user_to_update_password_on_login"] = (
            ask_user_to_update_password_on_login
        )

    response = requests.put(url, json=json, auth=_ApiKeyAuth(integration_api_key))
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise UpdateUserPasswordException(response.json())
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when updating password")

    return True


def _clear_user_password(auth_url, integration_api_key, user_id) -> bool:
    if not _is_valid_id(user_id):
        return False

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}/clear_password"
    response = requests.put(url, auth=_ApiKeyAuth(integration_api_key))
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise UpdateUserEmailException(response.json())
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when updating user email")

    return True


def _update_user_email(
    auth_url, integration_api_key, user_id, new_email, require_email_confirmation
) -> bool:
    if not _is_valid_id(user_id):
        return False

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}/email"
    json = {
        "new_email": new_email,
        "require_email_confirmation": require_email_confirmation,
    }

    response = requests.put(url, json=json, auth=_ApiKeyAuth(integration_api_key))
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise UpdateUserEmailException(response.json())
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when updating user email")

    return True


def _enable_user_can_create_orgs(auth_url, integration_api_key, user_id) -> bool:
    if not _is_valid_id(user_id):
        return False

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}/can_create_orgs/enable"
    response = requests.put(url, auth=_ApiKeyAuth(integration_api_key))

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when enabling can_create_orgs")

    return True


def _disable_user_can_create_orgs(auth_url, integration_api_key, user_id) -> bool:
    if not _is_valid_id(user_id):
        return False

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}/can_create_orgs/disable"
    response = requests.put(url, auth=_ApiKeyAuth(integration_api_key))

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when disabling can_create_orgs")

    return True


####################
#       DELETE     #
####################
def _delete_user(auth_url, integration_api_key, user_id) -> bool:
    if not _is_valid_id(user_id):
        return False

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}"
    response = requests.delete(url, auth=_ApiKeyAuth(integration_api_key))
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when deleting user")

    return True


####################
#       HELPERS    #
####################


def _validate_personal_api_key(auth_url, integration_api_key, api_key_token) -> PersonalApiKeyValidation:
    api_key_validation = _validate_api_key(auth_url, integration_api_key, api_key_token)
    if not api_key_validation.user or api_key_validation.org:
        raise EndUserApiKeyException({"api_key_token": ["Not a personal API Key"]})
    return PersonalApiKeyValidation(
        user=api_key_validation.user,
        metadata=api_key_validation.metadata,
    )
