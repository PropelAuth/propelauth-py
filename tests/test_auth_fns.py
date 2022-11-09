import pytest

from propelauth_py.errors import ForbiddenException
from tests.auth_helpers import create_access_token, orgs_to_org_id_map, random_org, random_user_id

def test_validate_minimum_org_role_and_get_org(auth, rsa_keys):
    user_id = random_user_id()
    org = random_org("Admin")
    org["inherited_user_roles_plus_current_role"] = ["Admin", "Member"]
    org_id_to_org_member_info = orgs_to_org_id_map([org])
    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem)

    try:
        auth.validate_access_token_and_get_user_with_org_by_minimum_role("Bearer " + access_token, org["org_id"], "Admin")
    except Exception as exc:
        assert False, f"'validate_access_token_and_get_user_with_org_by_minimum_role with Admin' raised an exception {exc}"

    try:
        auth.validate_access_token_and_get_user_with_org_by_minimum_role("Bearer " + access_token, org["org_id"], "Member")
    except Exception as exc:
        assert False, f"'validate_access_token_and_get_user_with_org_by_minimum_role with Member' raised an exception {exc}"


def test_validate_exact_org_role_and_get_org(auth, rsa_keys):
    user_id = random_user_id()
    org = random_org("Admin")
    org["inherited_user_roles_plus_current_role"] = ["Admin", "Member"]
    org_id_to_org_member_info = orgs_to_org_id_map([org])
    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem)

    try:
        auth.validate_access_token_and_get_user_with_org_by_exact_role("Bearer " + access_token, org["org_id"], "Admin")
    except Exception as exc:
        assert False, f"'validate_access_token_and_get_user_with_org_by_exact_role with Admin' raised an exception {exc}"

    with pytest.raises(ForbiddenException):
        auth.validate_access_token_and_get_user_with_org_by_exact_role("Bearer " + access_token, org["org_id"], "Member")

def test_validate_permission_and_get_org(auth, rsa_keys):
    user_id = random_user_id()
    org = random_org("Admin")
    org["user_permissions"] = ["read", "write"]
    org_id_to_org_member_info = orgs_to_org_id_map([org])
    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem)

    try:
        auth.validate_access_token_and_get_user_with_org_by_permission("Bearer " + access_token, org["org_id"], "read")
    except Exception as exc:
        assert False, f"'validate_access_token_and_get_user_with_org_by_permission with read' raised an exception {exc}"

    with pytest.raises(ForbiddenException):
        auth.validate_access_token_and_get_user_with_org_by_permission("Bearer " + access_token, org["org_id"], "delete")


def test_validate_all_permissions_and_get_org(auth, rsa_keys):
    user_id = random_user_id()
    org = random_org("Admin")
    org["user_permissions"] = ["read", "write"]
    org_id_to_org_member_info = orgs_to_org_id_map([org])
    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem)

    try:
        auth.validate_access_token_and_get_user_with_org_by_all_permissions("Bearer " + access_token, org["org_id"], ["read", "write"])
    except Exception as exc:
        assert False, f"'validate_access_token_and_get_user_with_org_by_all_permissions with read, write' raised an exception {exc}"

    with pytest.raises(ForbiddenException):
        auth.validate_access_token_and_get_user_with_org_by_all_permissions("Bearer " + access_token, org["org_id"], ["read", "write", "delete"])

