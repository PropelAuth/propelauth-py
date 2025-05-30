import datetime

import jwt

from propelauth_py.errors import UnauthorizedException
from propelauth_py.user import _to_user
from propelauth_py.logging_config import get_logger, should_log_exceptions

OPTIONS = {
    "verify_signature": True,
    "verify_exp": True,
    "verify_iat": True,
    "verify_iss": True,
    "verify_aud": False,
    "require": ["exp", "iat", "iss"],
}


def _validate_access_token_and_get_user(access_token, token_verification_metadata):
    try:
        decoded_token = jwt.decode(
            access_token,
            token_verification_metadata.verifier_key,
            options=OPTIONS,
            issuer=token_verification_metadata.issuer,
            algorithms=["RS256"],
            leeway=datetime.timedelta(seconds=60),
        )
        return _to_user(decoded_token)
    except UnauthorizedException as e:
        raise e
    except Exception:
        if should_log_exceptions():
            get_logger().exception(
                "An error occurred while validating the access token"
            )
        raise UnauthorizedException.invalid_access_token()
