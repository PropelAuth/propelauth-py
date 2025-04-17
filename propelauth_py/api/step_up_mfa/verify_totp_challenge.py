import requests

from propelauth_py.api import _ApiKeyAuth, _auth_hostname_header, BACKEND_API_BASE_URL
from propelauth_py.errors import (
    BadRequestException,
    RateLimitedException,
    UserNotFoundException,
    MfaNotEnabledException,
    IncorrectMfaCodeException,
    FeatureGatedException,
)
from propelauth_py.types.step_up_mfa import StepUpMfaVerifyTotpResponse

ENDPOINT_URL = f"{BACKEND_API_BASE_URL}/api/backend/v1/mfa/step-up/verify-totp"


def _verify_step_up_totp_challenge(
    auth_hostname,
    integration_api_key,
    action_type,
    user_id,
    code,
    grant_type,
    valid_for_seconds,
) -> StepUpMfaVerifyTotpResponse:
    url = ENDPOINT_URL
    json = {
        "action_type": action_type,
        "user_id": user_id,
        "code": code,
        "grant_type": grant_type,
        "valid_for_seconds": valid_for_seconds,
    }

    response = requests.post(
        url,
        json=json,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.ok:
        json_response = response.json()
        return StepUpMfaVerifyTotpResponse(
            step_up_grant=json_response.get("step_up_grant")
        )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)

    try:
        error_response = response.json()
        error_code = error_response.get("error_code")
        if error_code == "user_not_found":
            raise UserNotFoundException()
        elif error_code == "mfa_not_enabled":
            raise MfaNotEnabledException()
        elif error_code == "incorrect_mfa_code":
            raise IncorrectMfaCodeException()
        elif error_code == "feature_gated":
            raise FeatureGatedException()
        elif error_code == "invalid_request_fields":
            raise BadRequestException(error_response.get("field_to_errors", {}))
        else:
            raise RuntimeError(
                f"Unknown error when verifying step up totp challenge: {error_response}"
            )
    except requests.exceptions.JSONDecodeError:
        raise RuntimeError("Unknown error when verying step up totp challenge")
