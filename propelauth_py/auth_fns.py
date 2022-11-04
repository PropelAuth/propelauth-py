from propelauth_py.errors import UnauthorizedException, ForbiddenException
from propelauth_py.jwt import _validate_access_token_and_get_user
from propelauth_py.user import UserAndOrgMemberInfo


def wrap_validate_access_token_and_get_user(token_verification_metadata):
    def validate_access_token_and_get_user(authorization_header):
        access_token = _extract_token_from_authorization_header(authorization_header)
        user = _validate_access_token_and_get_user(access_token, token_verification_metadata)
        return user

    return validate_access_token_and_get_user


def wrap_validate_access_token_and_get_user_with_org(token_verification_metadata):
    def validate_access_token_and_get_user_with_org(authorization_header, required_org_id, minimum_required_role=None):
        access_token = _extract_token_from_authorization_header(authorization_header)
        user = _validate_access_token_and_get_user(access_token, token_verification_metadata)
        org_member_info = validate_org_access_and_get_org(user, required_org_id, minimum_required_role)
        return UserAndOrgMemberInfo(user, org_member_info)

    return validate_access_token_and_get_user_with_org


def validate_org_access_and_get_org(user, required_org_id, required_role):
    if required_org_id is None:
        raise ForbiddenException.unknown_required_org()

    org_id_to_org_member_info = user.org_id_to_org_member_info
    if org_id_to_org_member_info is None:
        raise ForbiddenException.user_not_member_of_org(required_org_id)

    org_member_info = org_id_to_org_member_info.get(required_org_id)
    if org_member_info is None:
        raise ForbiddenException.user_not_member_of_org(required_org_id)

    if required_role is not None and not org_member_info.can_do_role(required_role):
        raise ForbiddenException.user_doesnt_have_required_role()

    return org_member_info


def _extract_token_from_authorization_header(authorization_header):
    if authorization_header is None or authorization_header == "":
        raise UnauthorizedException.no_header_found()

    auth_header_parts = authorization_header.split(" ")
    if len(auth_header_parts) != 2 or auth_header_parts[0].lower() != "bearer":
        raise UnauthorizedException.invalid_header_found()

    return auth_header_parts[1]
