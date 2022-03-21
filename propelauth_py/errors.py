class UnauthorizedException(Exception):
    def __init__(self, message):
        self.message = message

    @staticmethod
    def no_header_found():
        return UnauthorizedException("No authorization header found")

    @staticmethod
    def invalid_header_found():
        return UnauthorizedException("Invalid authorization header. Expected: Bearer {accessToken}")

    @staticmethod
    def invalid_access_token():
        return UnauthorizedException("Invalid access token")

    @staticmethod
    def invalid_payload_in_access_token():
        return UnauthorizedException("Invalid payload in token")


class UnexpectedException(Exception):
    def __init__(self, message):
        self.message = message

    @staticmethod
    def invalid_minimum_required_role():
        return UnexpectedException(
            "Unknown minimum required role"
        )

    @staticmethod
    def invalid_user_role():
        return UnexpectedException(
            "Invalid user role. Try restarting the server to get the latest role config"
        )


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
    def user_less_than_minimum_role():
        return ForbiddenException("User's role in org doesn't meet minimum required role")
