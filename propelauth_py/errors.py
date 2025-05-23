class CreateUserException(Exception):
    def __init__(self, field_to_errors):
        self.field_to_errors = field_to_errors


class UpdateUserMetadataException(Exception):
    def __init__(self, field_to_errors):
        self.field_to_errors = field_to_errors


class InviteUserToOrgException(Exception):
    def __init__(self, field_to_errors):
        self.field_to_errors = field_to_errors


class UpdateUserPasswordException(Exception):
    def __init__(self, field_to_errors):
        self.field_to_errors = field_to_errors


class UpdateUserEmailException(Exception):
    def __init__(self, field_to_errors):
        self.field_to_errors = field_to_errors


class BadRequestException(Exception):
    def __init__(self, field_to_errors):
        self.field_to_errors = field_to_errors


class UserNotFoundException(Exception):
    pass


class EndUserApiKeyException(Exception):
    def __init__(self, field_to_errors):
        self.field_to_errors = field_to_errors


class EndUserApiKeyNotFoundException(Exception):
    pass


class EndUserApiKeyRateLimitedException(Exception):
    def __init__(self, field_to_errors):
        self.wait_seconds = field_to_errors.get("wait_seconds")
        self.user_facing_error = field_to_errors.get("user_facing_error")
        self.error_code = field_to_errors.get("error_code")
        self.field_to_errors = field_to_errors


class RateLimitedException(Exception):
    def __init__(self, error_message):
        self.error_message = error_message


class MfaNotEnabledException(Exception):
    pass


class IncorrectMfaCodeException(Exception):
    pass


class FeatureGatedException(Exception):
    def __init__(self, message="Feature is not available on current plan"):
        self.message = message


class StepUpMfaGrantNotFoundException(Exception):
    def __init__(self, message="The grant you provided was not found"):
        self.message = message


class UnauthorizedException(Exception):
    def __init__(self, message):
        self.message = message

    @staticmethod
    def no_header_found():
        return UnauthorizedException("No authorization header found")

    @staticmethod
    def invalid_header_found():
        return UnauthorizedException(
            "Invalid authorization header. Expected: Bearer {accessToken}"
        )

    @staticmethod
    def invalid_access_token():
        return UnauthorizedException("Invalid access token")

    @staticmethod
    def invalid_payload_in_access_token():
        return UnauthorizedException("Invalid payload in token")


class ForbiddenException(Exception):
    def __init__(self, message):
        self.message = message

    @staticmethod
    def unknown_required_org():
        return ForbiddenException("Required org is unspecified")

    @staticmethod
    def user_not_member_of_org(org_id):
        return ForbiddenException("User is not a member of org {}".format(org_id))

    @staticmethod
    def user_doesnt_have_required_role():
        return ForbiddenException("User doesn't have required role")

    @staticmethod
    def user_doesnt_have_required_permission():
        return ForbiddenException("User doesn't have required permission")
