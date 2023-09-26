import requests
from propelauth_py.api import _ApiKeyAuth, _is_valid_id
from propelauth_py.errors import BadRequestException, UserNotFoundException

ENDPOINT_PATH = "/api/backend/v1/access_token"


def _create_access_token(auth_url, integration_api_key, user_id, duration_in_minutes):
    if not _is_valid_id(user_id):
        raise UserNotFoundException()

    url = auth_url + ENDPOINT_PATH
    json = {"user_id": user_id, "duration_in_minutes": duration_in_minutes}
    response = requests.post(url, json=json, auth=_ApiKeyAuth(integration_api_key))
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif response.status_code == 403:
        raise UserNotFoundException()
    elif response.status_code == 404:
        raise RuntimeError("Access token creation is not enabled")
    elif not response.ok:
        raise RuntimeError("Unknown error when creating access token")

    return response.json()
