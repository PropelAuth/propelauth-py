from collections import namedtuple
from enum import Enum
from uuid import UUID

TokenVerificationMetadata = namedtuple(
    "TokenVerificationMetadata", ["verifier_key", "issuer"]
)

from requests.auth import AuthBase


class OrgQueryOrderBy(str, Enum):
    CREATED_AT_ASC = "CREATED_AT_ASC"
    CREATED_AT_DESC = "CREATED_AT_DESC"
    NAME = "NAME"


class UserQueryOrderBy(str, Enum):
    CREATED_AT_ASC = "CREATED_AT_ASC"
    CREATED_AT_DESC = "CREATED_AT_DESC"
    LAST_ACTIVE_AT_ASC = "LAST_ACTIVE_AT_ASC"
    LAST_ACTIVE_AT_DESC = "LAST_ACTIVE_AT_DESC"
    EMAIL = "EMAIL"
    USERNAME = "USERNAME"


class _ApiKeyAuth(AuthBase):
    """Attaches API Key Authentication to the given Request object."""

    def __init__(self, integration_api_key):
        self.integration_api_key = integration_api_key

    def __call__(self, r):
        r.headers["Authorization"] = "Bearer " + self.integration_api_key
        return r


def remove_bearer_if_exists(token: str) -> str:
    if not token:
        return token
    elif token.lower().startswith("bearer "):
        return token[7:]
    else:
        return token


def _format_params(params):
    return {
        key: _format_param(value) for key, value in params.items() if value is not None
    }


def _format_param(param):
    if type(param) == bool:
        if param:
            return "true"
        else:
            return "false"
    else:
        return param


def _is_valid_id(identifier):
    try:
        uuid_obj = UUID(identifier, version=4)
        return str(uuid_obj) == identifier
    except ValueError:
        return False


def _is_valid_hex(identifier):
    try:
        int(identifier, 16)
        return True
    except ValueError:
        return False
