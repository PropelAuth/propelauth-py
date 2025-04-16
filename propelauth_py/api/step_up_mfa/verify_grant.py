import requests

from propelauth_py.api import _ApiKeyAuth, _auth_hostname_header, BACKEND_API_BASE_URL
from propelauth_py.errors import (
    BadRequestException,
    RateLimitedException,
    FeatureGatedException,
)

ENDPOINT_URL = f"{BACKEND_API_BASE_URL}/api/backend/v1/mfa/step-up/verify-grant"


def _verify_step_up_grant(
    auth_hostname,
    integration_api_key,
    action_type,
    user_id,
    grant,
) -> bool:
    url = ENDPOINT_URL
    json = {
        "action_type": action_type,
        "user_id": user_id,
        "grant": grant,
    }

    response = requests.post(
        url,
        json=json,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.ok:
        return True

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)

    try:
        error_response = response.json()
        error_code = error_response.get("error_code")
        if error_code == "invalid_request_fields":
            field_to_errors = error_response.get("field_errors", {})
            if field_to_errors.get("grant") == "grant_not_found":
                return False
            raise BadRequestException(error_response.get("user_facing_errors", {}))
        elif error_code == "feature_gated":
            raise FeatureGatedException()
        else:
            raise RuntimeError(
                f"Unknown error when verifying step up grant: {error_response}"
            )
    except requests.exceptions.JSONDecodeError:
        raise RuntimeError("Unknown error when verifying step up grant")
