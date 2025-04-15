from typing import Dict, Optional, Union, Literal
from dataclasses import dataclass
from enum import Enum


class StepUpMfaTokenType(str, Enum):
    ONE_TIME_USE = "ONE_TIME_USE"
    TIME_BASED = "TIME_BASED"


@dataclass
class StepUpMfaVerifyTotpSuccessResponse:
    step_up_grant: str
    success: Literal[True] = True


@dataclass
class StepUpMfaVerifyTotpInvalidRequestErrorResponse:
    message: str
    user_facing_errors: Optional[Dict[str, str]]
    success: Literal[False] = False
    error_code: Literal["invalid_request_fields"] = "invalid_request_fields"


@dataclass
class StepUpMfaVerifyTotpStandardErrorResponse:
    error_code: Literal["user_not_found", "incorrect_mfa_code", "mfa_not_enabled", "feature_gated", "unexpected_error"]
    message: str
    success: Literal[False] = False


StepUpMfaVerifyTotpErrorResponse = Union[StepUpMfaVerifyTotpInvalidRequestErrorResponse, StepUpMfaVerifyTotpStandardErrorResponse]
StepUpMfaVerifyTotpResponse = Union[StepUpMfaVerifyTotpSuccessResponse, StepUpMfaVerifyTotpErrorResponse]


@dataclass
class StepUpMfaVerifyGrantSuccessResponse:
    success: Literal[True] = True


@dataclass
class StepUpMfaVerifyGrantInvalidRequestErrorResponse:
    message: str
    user_facing_errors: Optional[Dict[str, str]]
    success: Literal[False] = False
    error_code: Literal["invalid_request_fields"] = "invalid_request_fields"


@dataclass
class StepUpMfaVerifyGrantStandardErrorResponse:
    error_code: Literal["grant_not_found", "feature_gated", "unexpected_error"]
    message: str
    success: Literal[False] = False


StepUpMfaVerifyGrantErrorResponse = Union[StepUpMfaVerifyGrantInvalidRequestErrorResponse, StepUpMfaVerifyGrantStandardErrorResponse]
StepUpMfaVerifyGrantResponse = Union[StepUpMfaVerifyGrantSuccessResponse, StepUpMfaVerifyGrantErrorResponse]
