import requests
from propelauth_py.api import _ApiKeyAuth, _is_valid_id
from propelauth_py.errors import BadRequestException, UserNotFoundException, RateLimitedException

ENDPOINT_PATH = "/api/backend/v1/access_token"

class CreateAccessTokenResponse:
    def __init__(
        self,
        access_token: str,
    ):
        self.access_token = access_token

    def __repr__(self): 
        return (
            f"CreateAccessTokenResponse(access_token={self.access_token}"
        )
    def __eq__(self, other):
        return isinstance(other, CreateAccessTokenResponse)

def _create_access_token(auth_url, integration_api_key, user_id, duration_in_minutes) -> CreateAccessTokenResponse:
    if not _is_valid_id(user_id):
        raise UserNotFoundException()

    url = auth_url + ENDPOINT_PATH
    json = {"user_id": user_id, "duration_in_minutes": duration_in_minutes}
    response = requests.post(url, json=json, auth=_ApiKeyAuth(integration_api_key))
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif response.status_code == 403:
        raise UserNotFoundException()
    elif response.status_code == 404:
        raise RuntimeError("Access token creation is not enabled")
    elif not response.ok:
        raise RuntimeError("Unknown error when creating access token")

    json_response = response.json()
    return CreateAccessTokenResponse(
        access_token=json_response.get('access_token')
    )
