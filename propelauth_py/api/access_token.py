import requests
from propelauth_py.api import _ApiKeyAuth, _is_valid_id, _auth_hostname_header, BACKEND_API_BASE_URL
from propelauth_py.errors import BadRequestException, UserNotFoundException, RateLimitedException

ENDPOINT_URL = f"{BACKEND_API_BASE_URL}/api/backend/v1/access_token"

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

def _create_access_token(auth_hostname, integration_api_key, user_id, duration_in_minutes, active_org_id) -> CreateAccessTokenResponse:
    if not _is_valid_id(user_id):
        raise UserNotFoundException()

    url = ENDPOINT_URL
    json = {"user_id": user_id, "duration_in_minutes": duration_in_minutes}
    if active_org_id:
        json["active_org_id"] = active_org_id
        
    response = requests.post(
        url,
        json=json,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

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
