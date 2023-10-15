import requests

from propelauth_py.api import _ApiKeyAuth
from propelauth_py.errors import BadRequestException

ENDPOINT_PATH = "/api/backend/v1/migrate_user"


def _migrate_user_from_external_source(
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
    properties=None,
):
    url = auth_url + f"{ENDPOINT_PATH}/"
    json = {
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
    }
    if properties is not None:
        json["properties"] = properties

    response = requests.post(url, json=json, auth=_ApiKeyAuth(integration_api_key))
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif not response.ok:
        raise RuntimeError("Unknown error when migrating user")

    return response.json()
