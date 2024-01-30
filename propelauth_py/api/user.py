import requests

from propelauth_py.api import _ApiKeyAuth, _format_params, _is_valid_id
from propelauth_py.api.end_user_api_keys import _validate_api_key
from propelauth_py.errors import (
    CreateUserException,
    EndUserApiKeyException,
    InviteUserToOrgException,
    UpdateUserEmailException,
    UpdateUserMetadataException,
    UpdateUserPasswordException,
)

ENDPOINT_PATH = "/api/backend/v1/user"


####################
#       GET        #
####################
def _fetch_user_metadata_by_user_id(
    auth_url, integration_api_key, user_id, include_orgs=False
):
    if not _is_valid_id(user_id):
        return None

    user_info_url = auth_url + f"{ENDPOINT_PATH}/{user_id}"
    query = {"include_orgs": include_orgs}
    return _fetch_user_metadata_by_query(integration_api_key, user_info_url, query)


def _fetch_user_signup_query_params_by_user_id(
    auth_url,
    integration_api_key,
    user_id,
):
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
    elif response.status_code == 404:
        return None
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching user signup query params")

    return response.json()


def _fetch_user_metadata_by_email(
    auth_url, integration_api_key, email, include_orgs=False
):
    user_info_url = auth_url + f"{ENDPOINT_PATH}/email"
    query = {"include_orgs": include_orgs, "email": email}
    return _fetch_user_metadata_by_query(integration_api_key, user_info_url, query)


def _fetch_user_metadata_by_username(
    auth_url, integration_api_key, username, include_orgs=False
):
    user_info_url = auth_url + f"{ENDPOINT_PATH}/username"
    query = {"include_orgs": include_orgs, "username": username}
    return _fetch_user_metadata_by_query(integration_api_key, user_info_url, query)


def _fetch_user_metadata_by_query(integration_api_key, user_info_url, query):
    response = requests.get(
        user_info_url,
        params=_format_params(query),
        auth=_ApiKeyAuth(integration_api_key),
    )
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 400:
        raise ValueError("Bad request: " + response.text)
    elif response.status_code == 404:
        return None
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching user metadata")

    return response.json()


def _fetch_batch_user_metadata_by_user_ids(
    auth_url, integration_api_key, user_ids, include_orgs
):
    user_info_url = auth_url + f"{ENDPOINT_PATH}/user_ids"
    params = {"include_orgs": include_orgs}
    body = {"user_ids": user_ids}
    return _fetch_batch_user_metadata_by_query(
        user_info_url, integration_api_key, params, body, lambda x: x["user_id"]
    )


def _fetch_batch_user_metadata_by_emails(
    auth_url, integration_api_key, emails, include_orgs
):
    user_info_url = auth_url + f"{ENDPOINT_PATH}/emails"
    params = {"include_orgs": include_orgs}
    body = {"emails": emails}
    return _fetch_batch_user_metadata_by_query(
        user_info_url, integration_api_key, params, body, lambda x: x["email"]
    )


def _fetch_batch_user_metadata_by_usernames(
    auth_url, integration_api_key, usernames, include_orgs
):
    user_info_url = auth_url + f"{ENDPOINT_PATH}/usernames"
    params = {"include_orgs": include_orgs}
    body = {"usernames": usernames}
    return _fetch_batch_user_metadata_by_query(
        user_info_url, integration_api_key, params, body, lambda x: x["username"]
    )


def _fetch_batch_user_metadata_by_query(
    user_info_url, integration_api_key, params, body, key_fn
):
    response = requests.post(
        user_info_url,
        params=_format_params(params),
        json=body,
        auth=_ApiKeyAuth(integration_api_key),
    )
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
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
):
    url = auth_url + f"{ENDPOINT_PATH}/query"
    params = {
        "page_size": page_size,
        "page_number": page_number,
        "order_by": order_by,
        "email_or_username": email_or_username,
        "include_orgs": include_orgs,
    }
    response = requests.get(
        url, params=_format_params(params), auth=_ApiKeyAuth(integration_api_key)
    )
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 400:
        raise ValueError("Bad request: " + response.text)
    elif response.status_code == 426:
        raise RuntimeError(
            "Cannot use organizations unless B2B support is enabled. Enable it in your PropelAuth "
            "dashboard."
        )
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching orgs by query")

    return response.json()


def _fetch_users_in_org(
    auth_url, integration_api_key, org_id, page_size, page_number, include_orgs, role
):
    if not _is_valid_id(org_id):
        return {
            "users": [],
            "total_users": 0,
            "current_page": page_number,
            "page_size": page_size,
            "has_more_results": False,
        }

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
    elif response.status_code == 400:
        raise ValueError("Bad request: " + response.text)
    elif response.status_code == 426:
        raise RuntimeError(
            "Cannot use organizations unless B2B support is enabled. Enable it in your PropelAuth "
            "dashboard."
        )
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching users in org")

    return response.json()


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
):
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
    response = requests.post(url, json=json, auth=_ApiKeyAuth(integration_api_key))
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 400:
        raise CreateUserException(response.json())
    elif not response.ok:
        raise RuntimeError("Unknown error when creating user")

    return response.json()


def _disable_user(auth_url, integration_api_key, user_id):
    if not _is_valid_id(user_id):
        return False

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}/disable"
    response = requests.post(url, auth=_ApiKeyAuth(integration_api_key))
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when disabling user")

    return True


def _enable_user(auth_url, integration_api_key, user_id):
    if not _is_valid_id(user_id):
        return False

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}/enable"
    response = requests.post(url, auth=_ApiKeyAuth(integration_api_key))
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when enabling user")

    return True


def _disable_user_2fa(auth_url, integration_api_key, user_id):
    if not _is_valid_id(user_id):
        return False

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}/disable_2fa"
    response = requests.post(url, auth=_ApiKeyAuth(integration_api_key))

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when enabling user")

    return True


def _invite_user_to_org(auth_url, integration_api_key, email, org_id, role):
    if not _is_valid_id(org_id):
        return False

    endpoint_path = "/api/backend/v1/invite_user"
    url = auth_url + endpoint_path
    json = {
        "email": email,
        "org_id": org_id,
        "role": role,
    }
    response = requests.post(url, json=json, auth=_ApiKeyAuth(integration_api_key))

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
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

    return response.text


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
):
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
):
    if not _is_valid_id(user_id):
        return False

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}/password"
    json = {"password": password}
    if ask_user_to_update_password_on_login is not None:
        json[
            "ask_user_to_update_password_on_login"
        ] = ask_user_to_update_password_on_login

    response = requests.put(url, json=json, auth=_ApiKeyAuth(integration_api_key))
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 400:
        raise UpdateUserPasswordException(response.json())
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when updating password")

    return True


def _clear_user_password(auth_url, integration_api_key, user_id):
    if not _is_valid_id(user_id):
        return False

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}/clear_password"
    response = requests.put(url, auth=_ApiKeyAuth(integration_api_key))
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 400:
        raise UpdateUserEmailException(response.json())
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when updating user email")

    return True


def _update_user_email(
    auth_url, integration_api_key, user_id, new_email, require_email_confirmation
):
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
    elif response.status_code == 400:
        raise UpdateUserEmailException(response.json())
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when updating user email")

    return True


def _enable_user_can_create_orgs(auth_url, integration_api_key, user_id):
    if not _is_valid_id(user_id):
        return False

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}/can_create_orgs/enable"
    response = requests.put(url, auth=_ApiKeyAuth(integration_api_key))

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when enabling can_create_orgs")

    return True


def _disable_user_can_create_orgs(auth_url, integration_api_key, user_id):
    if not _is_valid_id(user_id):
        return False

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}/can_create_orgs/disable"
    response = requests.put(url, auth=_ApiKeyAuth(integration_api_key))

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when disabling can_create_orgs")

    return True


####################
#       DELETE     #
####################
def _delete_user(auth_url, integration_api_key, user_id):
    if not _is_valid_id(user_id):
        return False

    url = auth_url + f"{ENDPOINT_PATH}/{user_id}"
    response = requests.delete(url, auth=_ApiKeyAuth(integration_api_key))
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when deleting user")

    return True


####################
#       HELPERS    #
####################


def _validate_personal_api_key(auth_url, integration_api_key, api_key_token):
    api_key_validation = _validate_api_key(auth_url, integration_api_key, api_key_token)
    if not api_key_validation["user"] or api_key_validation["org"]:
        raise EndUserApiKeyException({"api_key_token": ["Not a personal API Key"]})
    return {
        "user": api_key_validation["user"],
        "metadata": api_key_validation["metadata"],
    }
