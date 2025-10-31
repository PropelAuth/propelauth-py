import requests
import json
import httpx
from propelauth_py.api import _ApiKeyAuth, _auth_hostname_header, BACKEND_API_BASE_URL, _get_async_headers
from propelauth_py.errors import (
    BadRequestException,
    RateLimitedException,
    FeatureGatedException,
)
from propelauth_py.types.step_up_mfa import VerifySmsChallengeResponse

ENDPOINT_URL = f"{BACKEND_API_BASE_URL}/api/backend/v1/mfa/step-up/phone/verify"


def _verify_sms_challenge(
    auth_hostname,
    integration_api_key,
    challenge_id,
    user_id,
    code,
) -> VerifySmsChallengeResponse:
    url = ENDPOINT_URL
    json = {
        "challenge_id": challenge_id,
        "user_id": user_id,
        "code": code,
    }

    response = requests.post(
        url,
        json=json,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.ok:
        json_response = response.json()
        return VerifySmsChallengeResponse(
            step_up_grant=json_response.get("step_up_grant")
        )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)

    try:
        error_response = response.json()
        error_code = error_response.get("error_code")
        if error_code == "invalid_request_fields":
            raise BadRequestException(error_response.get("user_facing_errors", {}))
        elif error_code == "feature_gated":
            raise FeatureGatedException()
        else:
            raise RuntimeError(
                f"Unknown error when verifying sms challenge: {error_response}"
            )
    except requests.exceptions.JSONDecodeError:
        raise RuntimeError("Unknown error when verifying sms challenge")
    
    
async def _verify_sms_challenge_async(
    httpx_client: httpx.AsyncClient,
    auth_hostname,
    integration_api_key,
    challenge_id,
    user_id,
    code,
) -> VerifySmsChallengeResponse:
    url = ENDPOINT_URL
    json_body = {
        "challenge_id": challenge_id,
        "user_id": user_id,
        "code": code,
    }


    response = await httpx_client.post(
        url=url,
        json=json_body,
        headers=_get_async_headers(auth_hostname=auth_hostname, integration_api_key=integration_api_key),
    )

    if response.is_success:
        json_response = response.json()
        return VerifySmsChallengeResponse(
            step_up_grant=json_response.get("step_up_grant")
        )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)

    try:
        error_response = response.json()
        error_code = error_response.get("error_code")
        if error_code == "invalid_request_fields":
            raise BadRequestException(error_response.get("user_facing_errors", {}))
        elif error_code == "feature_gated":
            raise FeatureGatedException()
        else:
            raise RuntimeError(
                f"Unknown error when verifying sms challenge: {error_response}"
            )
    except json.JSONDecodeError:
        raise RuntimeError("Unknown error when verifying sms challenge")
