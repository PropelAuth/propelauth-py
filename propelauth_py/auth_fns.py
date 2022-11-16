from propelauth_py.errors import UnauthorizedException, ForbiddenException
from propelauth_py.jwt import _validate_access_token_and_get_user
from propelauth_py.user import UserAndOrgMemberInfo

# wrapper functions

def wrap_validate_access_token_and_get_user(token_verification_metadata):
    def validate_access_token_and_get_user(authorization_header):
        access_token = _extract_token_from_authorization_header(authorization_header)
        user = _validate_access_token_and_get_user(access_token, token_verification_metadata)
        return user

    return validate_access_token_and_get_user


def wrap_validate_access_token_and_get_user_with_org(token_verification_metadata):
    def validate_access_token_and_get_user_with_org(authorization_header, required_org_id):
        access_token = _extract_token_from_authorization_header(authorization_header)
        user = _validate_access_token_and_get_user(access_token, token_verification_metadata)
        org_member_info = validate_org_access_and_get_org_member_info(user, required_org_id)
        return UserAndOrgMemberInfo(user, org_member_info)

    return validate_access_token_and_get_user_with_org


def wrap_validate_access_token_and_get_user_with_org_by_minimum_role(token_verification_metadata):
    def validate_access_token_and_get_user_with_org_by_minimum_role(authorization_header, required_org_id, minimum_required_role):
        access_token = _extract_token_from_authorization_header(authorization_header)
        user = _validate_access_token_and_get_user(access_token, token_verification_metadata)
        org_member_info = validate_minimum_org_role_and_get_org(user, required_org_id, minimum_required_role)
        return UserAndOrgMemberInfo(user, org_member_info)

    return validate_access_token_and_get_user_with_org_by_minimum_role


def wrap_validate_access_token_and_get_user_with_org_by_exact_role(token_verification_metadata):
    def validate_access_token_and_get_user_with_org_by_exact_role(authorization_header, required_org_id, required_role):
        access_token = _extract_token_from_authorization_header(authorization_header)
        user = _validate_access_token_and_get_user(access_token, token_verification_metadata)
        org_member_info = validate_exact_org_role_and_get_org(user, required_org_id, required_role)
        return UserAndOrgMemberInfo(user, org_member_info)

    return validate_access_token_and_get_user_with_org_by_exact_role


def wrap_validate_access_token_and_get_user_with_org_by_permission(token_verification_metadata):
    def validate_access_token_and_get_user_with_org_by_permission(authorization_header, required_org_id, permission):
        access_token = _extract_token_from_authorization_header(authorization_header)
        user = _validate_access_token_and_get_user(access_token, token_verification_metadata)
        org_member_info = validate_permission_and_get_org(user, required_org_id, permission)
        return UserAndOrgMemberInfo(user, org_member_info)

    return validate_access_token_and_get_user_with_org_by_permission


def wrap_validate_access_token_and_get_user_with_org_by_all_permissions(token_verification_metadata):
    def validate_access_token_and_get_user_with_org_by_all_permissions(authorization_header, required_org_id, permissions):
        access_token = _extract_token_from_authorization_header(authorization_header)
        user = _validate_access_token_and_get_user(access_token, token_verification_metadata)
        org_member_info = validate_all_permissions_and_get_org(user, required_org_id, permissions)
        return UserAndOrgMemberInfo(user, org_member_info)

    return validate_access_token_and_get_user_with_org_by_all_permissions

# validation functions


def validate_org_access_and_get_org_member_info(user, required_org_id):
    """performs basic verifications and returns the org member info"""
    if required_org_id is None:
        raise ForbiddenException.unknown_required_org()

    org_id_to_org_member_info = user.org_id_to_org_member_info
    if org_id_to_org_member_info is None:
        raise ForbiddenException.user_not_member_of_org(required_org_id)

    org_member_info = org_id_to_org_member_info.get(required_org_id)
    if org_member_info is None:
        raise ForbiddenException.user_not_member_of_org(required_org_id)

    return org_member_info


def validate_minimum_org_role_and_get_org(user, required_org_id, minimum_role):
    """returns the org is the user is or inherits from the role specified"""
    org_member_info = validate_org_access_and_get_org_member_info(user, required_org_id)

    if minimum_role is not None and not org_member_info.user_is_at_least_role(minimum_role):
        raise ForbiddenException.user_doesnt_have_required_role()

    return org_member_info


def validate_exact_org_role_and_get_org(user, required_org_id, exact_role):
    """returns the org is the user has the exact role specified"""
    org_member_info = validate_org_access_and_get_org_member_info(user, required_org_id)

    if exact_role is not None and not org_member_info.user_is_role(exact_role):
        raise ForbiddenException.user_doesnt_have_required_role()

    return org_member_info


def validate_permission_and_get_org(user, required_org_id, permission):
    """returns the org is the user has the permission specified"""
    org_member_info = validate_org_access_and_get_org_member_info(user, required_org_id)

    if permission is not None and not org_member_info.user_has_permission(permission):
        raise ForbiddenException.user_doesnt_have_required_permission()

    return org_member_info


def validate_all_permissions_and_get_org(user, required_org_id, permissions):
    """returns the org is the user has the permission specified"""
    org_member_info = validate_org_access_and_get_org_member_info(user, required_org_id)

    if permissions is not None and not org_member_info.user_has_all_permissions(permissions):
        raise ForbiddenException.user_doesnt_have_required_permission()

    return org_member_info

# helper functions

def _extract_token_from_authorization_header(authorization_header):
    if authorization_header is None or authorization_header == "":
        raise UnauthorizedException.no_header_found()

    auth_header_parts = authorization_header.split(" ")
    if len(auth_header_parts) != 2 or auth_header_parts[0].lower() != "bearer":
        raise UnauthorizedException.invalid_header_found()

    return auth_header_parts[1]
