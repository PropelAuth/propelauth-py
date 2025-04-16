from dataclasses import dataclass
from enum import Enum


class StepUpMfaGrantType(str, Enum):
    ONE_TIME_USE = "ONE_TIME_USE"
    TIME_BASED = "TIME_BASED"


@dataclass
class StepUpMfaVerifyTotpResponse:
    step_up_grant: str

    def __getitem__(self, key):
        return getattr(self, key)
