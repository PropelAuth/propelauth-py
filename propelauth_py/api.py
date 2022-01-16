from collections import namedtuple

import requests
from requests.auth import AuthBase

TokenVerificationMetadata = namedtuple("TokenVerificationMetadata", [
    "verifier_key", "issuer"
])


def _fetch_token_verification_metadata(auth_url: str, api_key: str,
                                       token_verification_metadata: TokenVerificationMetadata):
    if token_verification_metadata is not None:
        return token_verification_metadata

    token_verification_metadata_url = auth_url + "/api/v1/token_verification_metadata"
    response = requests.get(token_verification_metadata_url, auth=_ApiKeyAuth(api_key))
    if response.status_code == 401:
        raise ValueError("api_key is incorrect")
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


def _fetch_user_metadata_by_query(auth_url, api_key, query):
    user_info_url = auth_url + "/api/v1/user_info"
    response = requests.get(user_info_url, params=query, auth=_ApiKeyAuth(api_key))
    if response.status_code == 401:
        raise ValueError("api_key is incorrect")
    elif response.status_code == 400:
        raise ValueError("Bad request")
    elif response.status_code == 404:
        return None
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching user metadata")

    return response.json()


def _fetch_batch_user_metadata_by_query(auth_url, api_key, query_type, values):
    user_info_url = auth_url + "/api/v1/user_info/{}".format(query_type)
    response = requests.post(user_info_url, json=values, auth=_ApiKeyAuth(api_key))
    if response.status_code == 401:
        raise ValueError("api_key is incorrect")
    elif response.status_code == 400:
        raise ValueError("Bad request")
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching batch user metadata")

    return response.json()


class _ApiKeyAuth(AuthBase):
    """Attaches API Key Authentication to the given Request object."""

    def __init__(self, api_key):
        self.api_key = api_key

    def __call__(self, r):
        r.headers["Authorization"] = "Bearer " + self.api_key
        return r
