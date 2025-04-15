import requests
import json

from propelauth_py.api import (
    _ApiKeyAuth,
    BACKEND_API_BASE_URL,
    _auth_hostname_header,
)
from propelauth_py.types.step_up_mfa import (
    StepUpMfaTokenType,
    StepUpMfaVerifyTotpResponse,
    StepUpMfaVerifyTotpSuccessResponse,
    StepUpMfaVerifyTotpInvalidRequestErrorResponse,
    StepUpMfaVerifyTotpStandardErrorResponse,
    StepUpMfaVerifyGrantResponse,
    StepUpMfaVerifyGrantSuccessResponse,
    StepUpMfaVerifyGrantInvalidRequestErrorResponse,
    StepUpMfaVerifyGrantStandardErrorResponse,
)
from propelauth_py.errors import (
    UnauthorizedException,
    RateLimitedException,
)

STEP_UP_VERIFY_TOTP_ENDPOINT = (
    f"{BACKEND_API_BASE_URL}/api/backend/v1/mfa/step-up/verify-totp"
)
STEP_UP_VERIFY_GRANT_ENDPOINT = (
    f"{BACKEND_API_BASE_URL}/api/backend/v1/mfa/step-up/verify-grant"
)


def _verify_totp_challenge(
    auth_hostname: str,
    integration_api_key: str,
    action_type: str,
    user_id: str,
    code: str,
    token_type: StepUpMfaTokenType,
    valid_for_seconds: int,
) -> StepUpMfaVerifyTotpResponse:
    request_data = {
        "action_type": action_type,
        "user_id": user_id,
        "code": code,
        "token_type": token_type,
        "valid_for_seconds": valid_for_seconds,
    }

    response = requests.post(
        url=STEP_UP_VERIFY_TOTP_ENDPOINT,
        json=request_data,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    try:
        # Success case
        if response.status_code < 400:
            response_data = response.json()
            step_up_grant = response_data.get("step_up_grant")
            if not step_up_grant:
                raise RuntimeError(
                    "Received success response but missing step_up_grant"
                )
            return StepUpMfaVerifyTotpSuccessResponse(
                step_up_grant=step_up_grant,
            )

        error_response = response.json() if response.content else {}

        if (
            response.status_code == 401
            or error_response.get("error_code") == "unauthorized"
        ):
            raise UnauthorizedException("integration_api_key is incorrect")
        elif response.status_code == 429:
            raise RateLimitedException(response.text)
        elif error_response.get("error_code") == "user_not_found":
            return StepUpMfaVerifyTotpStandardErrorResponse(
                error_code="user_not_found",
                message=error_response.get("user_facing_error", "User not found"),
            )
        elif error_response.get("error_code") == "mfa_not_enabled":
            return StepUpMfaVerifyTotpStandardErrorResponse(
                error_code="mfa_not_enabled",
                message=error_response.get(
                    "user_facing_error", "MFA is not enabled for this user"
                ),
            )
        elif error_response.get("error_code") == "incorrect_mfa_code":
            return StepUpMfaVerifyTotpStandardErrorResponse(
                error_code="incorrect_mfa_code",
                message=error_response.get("user_facing_error", "Incorrect MFA code"),
            )
        elif error_response.get("error_code") == "invalid_request_fields":
            return StepUpMfaVerifyTotpInvalidRequestErrorResponse(
                message=error_response.get(
                    "user_facing_error", "Invalid request fields"
                ),
                user_facing_errors=error_response.get("user_facing_errors"),
            )
        elif error_response.get("error_code") == "feature_gated":
            return StepUpMfaVerifyTotpStandardErrorResponse(
                error_code="feature_gated",
                message=error_response.get(
                    "user_facing_error", "Feature is not available on current plan"
                ),
            )
        else:
            return StepUpMfaVerifyTotpStandardErrorResponse(
                error_code="unexpected_error",
                message=error_response.get(
                    "user_facing_error", "Unexpected error occurred"
                ),
            )
    except (json.JSONDecodeError, TypeError):
        raise RuntimeError("Failed to parse response")


def _verify_step_up_grant(
    auth_hostname: str,
    integration_api_key: str,
    action_type: str,
    user_id: str,
    grant: str,
) -> StepUpMfaVerifyGrantResponse:
    request_data = {
        "action_type": action_type,
        "user_id": user_id,
        "grant": grant,
    }

    response = requests.post(
        url=STEP_UP_VERIFY_GRANT_ENDPOINT,
        json=request_data,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    try:
        # Success case
        if response.status_code < 400:
            return StepUpMfaVerifyGrantSuccessResponse()

        error_response = response.json() if response.content else {}

        if (
            response.status_code == 401
            or error_response.get("error_code") == "unauthorized"
        ):
            raise UnauthorizedException("integration_api_key is incorrect")
        elif response.status_code == 429:
            raise RateLimitedException(response.text)
        elif error_response.get("error_code") == "invalid_request_fields":
            return StepUpMfaVerifyGrantInvalidRequestErrorResponse(
                message=error_response.get(
                    "user_facing_error", "Invalid request fields"
                ),
                user_facing_errors=error_response.get("user_facing_errors"),
            )
        elif error_response.get("error_code") == "token_not_found":
            return StepUpMfaVerifyGrantStandardErrorResponse(
                error_code="grant_not_found",
                message=error_response.get(
                    "user_facing_error", "The grant you provided was not found"
                ),
            )
        elif error_response.get("error_code") == "feature_gated":
            return StepUpMfaVerifyGrantStandardErrorResponse(
                error_code="feature_gated",
                message=error_response.get(
                    "user_facing_error", "Feature is not available on current plan"
                ),
            )
        else:
            return StepUpMfaVerifyGrantStandardErrorResponse(
                error_code="unexpected_error",
                message=error_response.get(
                    "user_facing_error", "Unexpected error occurred"
                ),
            )
    except (json.JSONDecodeError, TypeError):
        raise RuntimeError("Failed to parse response")
