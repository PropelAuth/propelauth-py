from datetime import timedelta

import pytest

from propelauth_py import UnauthorizedException
from propelauth_py.errors import ForbiddenException
from tests.auth_helpers import create_access_token, orgs_to_org_id_map, random_org, random_user_id, random_org_id
from tests.conftest import HTTP_BASE_AUTH_URL, generate_rsa_keys


def test_validate_without_auth(auth, rsa_keys):
    required_org_id = random_org_id()

    with pytest.raises(UnauthorizedException):
        auth.validate_access_token_and_get_user_with_org(None, required_org_id)


def test_validate_without_auth_2(auth, rsa_keys):
    required_org_id = random_org_id()

    with pytest.raises(UnauthorizedException):
        auth.validate_access_token_and_get_user_with_org("", required_org_id)


def test_validate_org_member_with_auth_but_no_org_membership(auth, rsa_keys):
    required_org_id = random_org_id()
    user_id = random_user_id()
    access_token = create_access_token({"user_id": user_id}, rsa_keys.private_pem)

    with pytest.raises(ForbiddenException):
        auth.validate_access_token_and_get_user_with_org("Bearer " + access_token, required_org_id)


def test_validate_org_member_with_auth_and_org_member(auth, rsa_keys):
    user_id = random_user_id()
    org = random_org("Owner")
    org_id_to_org_member_info = orgs_to_org_id_map([org])
    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem)

    user_and_org = auth.validate_access_token_and_get_user_with_org("Bearer " + access_token, org["org_id"])

    assert user_and_org.user.user_id == user_id
    assert user_and_org.org_member_info.org_id == org["org_id"]
    assert user_and_org.org_member_info.org_name == org["org_name"]
    assert user_and_org.org_member_info.user_assigned_role == "Owner"


def test_validate_org_member_with_auth_but_wrong_org_id(auth, rsa_keys):
    user_id = random_user_id()
    org = random_org("Owner")
    org_id_to_org_member_info = orgs_to_org_id_map([org])
    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem)

    # Pass wrong org_id as required
    wrong_org_id = random_org_id()
    with pytest.raises(ForbiddenException):
        auth.validate_access_token_and_get_user_with_org("Bearer " + access_token, wrong_org_id)


def test_validate_org_member_with_auth_but_no_permission(auth, rsa_keys):
    user_id = random_user_id()
    org = random_org("Member")
    org_id_to_org_member_info = orgs_to_org_id_map([org])
    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem)

    # Require at least admin, but the user is a member
    with pytest.raises(ForbiddenException):
        auth.validate_access_token_and_get_user_with_org_by_minimum_role("Bearer " + access_token, org["org_id"], "Admin")


def test_validate_org_member_with_auth_with_permission(auth, rsa_keys):
    user_id = random_user_id()
    org = random_org("Admin")
    org_id_to_org_member_info = orgs_to_org_id_map([org])
    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem)

    user_and_org = auth.validate_access_token_and_get_user_with_org_by_minimum_role("Bearer " + access_token, org["org_id"], "Admin")

    assert user_and_org.user.user_id == user_id
    assert user_and_org.org_member_info.org_id == org["org_id"]
    assert user_and_org.org_member_info.org_name == org["org_name"]
    assert user_and_org.org_member_info.user_assigned_role == "Admin"


def test_validate_org_member_with_bad_header(auth, rsa_keys):
    user_id = random_user_id()
    org = random_org("Admin")
    org_id_to_org_member_info = orgs_to_org_id_map([org])
    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem)

    with pytest.raises(UnauthorizedException):
        auth.validate_access_token_and_get_user_with_org("token " + access_token, org["org_id"])


def test_validate_org_member_with_wrong_token(auth, rsa_keys):
    required_org_id = random_org_id()

    with pytest.raises(UnauthorizedException):
        auth.validate_access_token_and_get_user_with_org("Bearer whatisthis", required_org_id)


def test_validate_org_member_with_expired_token(auth, rsa_keys):
    user_id = random_user_id()
    org = random_org("Owner")
    org_id_to_org_member_info = orgs_to_org_id_map([org])
    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem, expires_in=timedelta(minutes=-1))

    with pytest.raises(UnauthorizedException):
        auth.validate_access_token_and_get_user_with_org("Bearer" + access_token, org["org_id"])


def test_validate_org_member_with_bad_issuer(auth, rsa_keys):
    user_id = random_user_id()
    org = random_org("Owner")
    org_id_to_org_member_info = orgs_to_org_id_map([org])
    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem, issuer=HTTP_BASE_AUTH_URL)

    with pytest.raises(UnauthorizedException):
        auth.validate_access_token_and_get_user_with_org("Bearer" + access_token, org["org_id"])


def test_validate_org_member_with_wrong_key(auth, rsa_keys):
    user_id = random_user_id()
    org = random_org("Owner")
    org_id_to_org_member_info = orgs_to_org_id_map([org])

    incorrect_rsa_keys = generate_rsa_keys()
    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, incorrect_rsa_keys.private_pem, issuer=HTTP_BASE_AUTH_URL)

    with pytest.raises(UnauthorizedException):
        auth.validate_access_token_and_get_user_with_org("Bearer " + access_token, org["org_id"])
