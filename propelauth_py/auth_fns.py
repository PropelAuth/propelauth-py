from propelauth_py.errors import UnauthorizedException, UnexpectedException, ForbiddenException
from propelauth_py.jwt import _validate_access_token_and_get_user
from propelauth_py.user import UserAndOrgMemberInfo


def wrap_validate_access_token_and_get_user(token_verification_metadata):
    def validate_access_token_and_get_user(authorization_header):
        access_token = _extract_token_from_authorization_header(authorization_header)
        user = _validate_access_token_and_get_user(access_token, token_verification_metadata)
        return user

    return validate_access_token_and_get_user


def wrap_validate_access_token_and_get_user_with_org(token_verification_metadata, role_helper):
    def validate_access_token_and_get_user_with_org(authorization_header,
                                                    required_org_id,
                                                    minimum_required_role=None,
                                                    required_permissions=None):
        if required_permissions is None:
            required_permissions = []
        access_token = _extract_token_from_authorization_header(authorization_header)
        user = _validate_access_token_and_get_user(access_token, token_verification_metadata)
        org_member_info = validate_org_access_and_get_org(user,
                                                          required_org_id,
                                                          minimum_required_role,
                                                          required_permissions,
                                                          role_helper)
        return UserAndOrgMemberInfo(user, org_member_info)

    return validate_access_token_and_get_user_with_org


def validate_org_access_and_get_org(user, required_org_id, minimum_required_role, required_permissions, role_helper):
    if required_org_id is None:
        raise ForbiddenException.unknown_required_org()

    org_id_to_org_member_info = user.org_id_to_org_member_info
    if org_id_to_org_member_info is None:
        raise ForbiddenException.user_not_member_of_org(required_org_id)

    org_member_info = org_id_to_org_member_info.get(required_org_id)
    if org_member_info is None:
        raise ForbiddenException.user_not_member_of_org(required_org_id)

    if minimum_required_role is not None:
        _validate_user_role_is_at_least_minimum(org_member_info.user_role_name, minimum_required_role, role_helper)

    if required_permissions is not None and len(required_permissions) > 0:
        _validate_user_permissions_includes(org_member_info.user_role_name, required_permissions, role_helper)

    return org_member_info


def wrap_validate_org_access_and_get_org(role_helper):
    def _validate_org_access_and_get_org(user, required_org_id, minimum_required_role=None, required_permissions=None):
        if required_permissions is None:
            required_permissions = []
        return validate_org_access_and_get_org(user, required_org_id, minimum_required_role, required_permissions,
                                               role_helper)

    return _validate_org_access_and_get_org


def _extract_token_from_authorization_header(authorization_header):
    if authorization_header is None or authorization_header == "":
        raise UnauthorizedException.no_header_found()

    auth_header_parts = authorization_header.split(" ")
    if len(auth_header_parts) != 2 or auth_header_parts[0].lower() != "bearer":
        raise UnauthorizedException.invalid_header_found()

    return auth_header_parts[1]


def _validate_user_role_is_at_least_minimum(user_role, minimum_required_role, role_helper):
    if not role_helper.is_valid_role(user_role):
        raise UnexpectedException.invalid_user_role()

    if not role_helper.is_valid_role(minimum_required_role):
        raise UnexpectedException.invalid_minimum_required_role()

    if not role_helper.is_parent_or_equal_to(user_role, minimum_required_role):
        raise ForbiddenException.user_less_than_minimum_role()


def _validate_user_permissions_includes(user_role, required_permissions, role_helper):
    if not role_helper.is_valid_role(user_role):
        raise UnexpectedException.invalid_user_role()

    if not role_helper.role_includes_all_permissions(user_role, required_permissions):
        raise ForbiddenException.user_missing_permission()
