from typing import Optional
import requests
from propelauth_py.api import _ApiKeyAuth, TokenVerificationMetadata, _auth_hostname_header, BACKEND_API_BASE_URL
from propelauth_py.errors import RateLimitedException

ENDPOINT_URL = f"{BACKEND_API_BASE_URL}/api/v1/token_verification_metadata"


####################
#       GET        #
####################
def _fetch_token_verification_metadata(
    auth_hostname: str,
    integration_api_key: str,
    token_verification_metadata: Optional[TokenVerificationMetadata],
):
    if token_verification_metadata is not None:
        return token_verification_metadata

    token_verification_metadata_url = ENDPOINT_URL

    response = requests.get(
        token_verification_metadata_url,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise ValueError("Bad request")
    elif response.status_code == 404:
        raise ValueError("auth_url is incorrect")
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching token verification metadata")

    json_response = response.json()
    return TokenVerificationMetadata(
        verifier_key=json_response.get("verifier_key_pem"),
        issuer="https://" + auth_hostname,
    )
