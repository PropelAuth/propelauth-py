import requests
from propelauth_py.api import _ApiKeyAuth, _format_params, _is_valid_id
from propelauth_py.api.end_user_api_keys import _validate_api_key
from propelauth_py.errors import (
    BadRequestException,
    EndUserApiKeyException,
    UpdateUserMetadataException,
)


ENDPOINT_PATH = "/api/backend/v1/org"


####################
#       GET        #
####################
def _fetch_org(auth_url, integration_api_key, org_id):
    if not _is_valid_id(org_id):
        return None

    url = auth_url + f"{ENDPOINT_PATH}/{org_id}"
    response = requests.get(url, auth=_ApiKeyAuth(integration_api_key))
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 404:
        return None
    elif response.status_code == 426:
        raise RuntimeError(
            "Cannot use organizations unless B2B support is enabled. Enable it in your PropelAuth "
            "dashboard."
        )
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching org")

    return response.json()


def _fetch_org_by_query(
    auth_url, integration_api_key, page_size, page_number, order_by, name
):
    url = auth_url + f"{ENDPOINT_PATH}/query"
    params = {
        "page_size": page_size,
        "page_number": page_number,
        "order_by": order_by,
        "name": name,
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


####################
#       POST       #
####################
def _create_org(
    auth_url,
    integration_api_key,
    name,
    enable_auto_joining_by_domain=False,
    members_must_have_matching_domain=False,
    domain=None,
    max_users=None,
):
    url = auth_url + f"{ENDPOINT_PATH}/"
    json = {
        "name": name,
        "enable_auto_joining_by_domain": enable_auto_joining_by_domain,
        "members_must_have_matching_domain": members_must_have_matching_domain,
    }
    if domain:
        json["domain"] = domain
    if max_users is not None:
        json["max_users"] = max_users

    response = requests.post(url, json=json, auth=_ApiKeyAuth(integration_api_key))
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif not response.ok:
        raise RuntimeError("Unknown error when creating an org")

    return response.json()


def _allow_org_to_setup_saml_connection(auth_url, integration_api_key, org_id):
    if not _is_valid_id(org_id):
        return False

    url = auth_url + f"{ENDPOINT_PATH}/{org_id}/allow_saml"
    response = requests.post(url, auth=_ApiKeyAuth(integration_api_key))
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when allowing org to setup SAML connection")

    return True


def _disallow_org_to_setup_saml_connection(auth_url, integration_api_key, org_id):
    if not _is_valid_id(org_id):
        return False

    url = auth_url + f"{ENDPOINT_PATH}/{org_id}/disallow_saml"
    response = requests.post(url, auth=_ApiKeyAuth(integration_api_key))
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when allowing org to setup SAML connection")

    return True


def _add_user_to_org(auth_url, integration_api_key, user_id, org_id, role):
    url = auth_url + f"{ENDPOINT_PATH}/add_user"
    json = {"user_id": user_id, "org_id": org_id, "role": role}

    response = requests.post(url, json=json, auth=_ApiKeyAuth(integration_api_key))
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when adding a user to the org")

    return True


def _remove_user_from_org(auth_url, integration_api_key, user_id, org_id):
    url = auth_url + f"{ENDPOINT_PATH}/remove_user"
    json = {"user_id": user_id, "org_id": org_id}

    response = requests.post(url, json=json, auth=_ApiKeyAuth(integration_api_key))
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when removing a user from the org")

    return True


def _change_user_role_in_org(auth_url, integration_api_key, user_id, org_id, role):
    url = auth_url + f"{ENDPOINT_PATH}/change_role"
    json = {"user_id": user_id, "org_id": org_id, "role": role}

    response = requests.post(url, json=json, auth=_ApiKeyAuth(integration_api_key))
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when changing a user's role in the org")

    return True


####################
#     PATCH/PUT    #
####################
def _update_org_metadata(
    auth_url,
    integration_api_key,
    org_id,
    name=None,
    can_setup_saml=None,
    metadata=None,
    max_users=None,
    can_join_on_email_domain_match=None,  # In the backend, this is the `domain_autojoin` argument.
    members_must_have_email_domain_match=None,  # In the backend, this is the `domain_restrict` argument.
    domain=None,
    # TODO: Add `require_2fa_by` optional argument.
):
    if not _is_valid_id(org_id):
        return False

    url = auth_url + f"{ENDPOINT_PATH}/{org_id}"
    json = {}
    if name is not None:
        json["name"] = name
    if can_setup_saml is not None:
        json["can_setup_saml"] = can_setup_saml
    if metadata is not None:
        json["metadata"] = metadata
    if max_users is not None:
        json["max_users"] = max_users
    if can_join_on_email_domain_match is not None:
        json["autojoin_by_domain"] = can_join_on_email_domain_match
    if members_must_have_email_domain_match is not None:
        json["restrict_to_domain"] = members_must_have_email_domain_match
    if domain is not None:
        json["domain"] = domain

    response = requests.put(url, json=json, auth=_ApiKeyAuth(integration_api_key))
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 400:
        raise UpdateUserMetadataException(response.json())
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when updating org metadata")

    return True


####################
#      DELETE      #
####################


def _delete_org(auth_url, integration_api_key, org_id):
    if not _is_valid_id(org_id):
        return False

    url = auth_url + f"{ENDPOINT_PATH}/{org_id}"
    response = requests.delete(url, auth=_ApiKeyAuth(integration_api_key))

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when deleting org")

    return True


####################
#      HELPERS     #
####################


def _validate_org_api_key(auth_url, integration_api_key, api_key_token):
    api_key_validation = _validate_api_key(auth_url, integration_api_key, api_key_token)
    if not api_key_validation["org"]:
        raise EndUserApiKeyException({"api_key_token": ["Not an org API Key"]})
    return {
        "org": api_key_validation["org"],
        "metadata": api_key_validation["metadata"],
        "user": api_key_validation["user"],
        "user_in_org": api_key_validation["user_in_org"],
    }
