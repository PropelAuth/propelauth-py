from collections import namedtuple
import requests
from propelauth_py.api import _ApiKeyAuth, TokenVerificationMetadata

ENDPOINT_PATH = "/api/v1/token_verification_metadata"


####################
#       GET        #
####################
def _fetch_token_verification_metadata(
    auth_url: str,
    integration_api_key: str,
    token_verification_metadata: TokenVerificationMetadata,
):
    if token_verification_metadata is not None:
        return token_verification_metadata

    token_verification_metadata_url = auth_url + ENDPOINT_PATH
    response = requests.get(
        token_verification_metadata_url, auth=_ApiKeyAuth(integration_api_key)
    )
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 400:
        raise ValueError("Bad request")
    elif response.status_code == 404:
        raise ValueError("auth_url is incorrect")
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching token verification metadata")

    json_response = response.json()
    return TokenVerificationMetadata(
        verifier_key=json_response["verifier_key_pem"],
        issuer=auth_url,
    )
