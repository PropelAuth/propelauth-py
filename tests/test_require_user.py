from datetime import timedelta

import pytest

from propelauth_py import UnauthorizedException
from tests.auth_helpers import create_access_token, random_user_id
from tests.conftest import HTTP_BASE_AUTH_URL, generate_rsa_keys


def test_validate_without_header(auth, rsa_keys):
    with pytest.raises(UnauthorizedException):
        auth.validate_access_token_and_get_user(None)


def test_validate_with_header(auth, rsa_keys):
    user_id = random_user_id()
    access_token = create_access_token({"user_id": user_id}, rsa_keys.private_pem)
    user = auth.validate_access_token_and_get_user("Bearer " + access_token)
    assert user.user_id == user_id
    assert user.org_id_to_org_member_info is None


def test_validate_with_invalid_header(auth, rsa_keys):
    user_id = random_user_id()
    access_token = create_access_token({"user_id": user_id}, rsa_keys.private_pem)
    with pytest.raises(UnauthorizedException):
        auth.validate_access_token_and_get_user("token " + access_token)


def test_validate_with_wrong_token(auth, rsa_keys):
    with pytest.raises(UnauthorizedException):
        auth.validate_access_token_and_get_user("Bearer whatisthis")


def test_validate_with_expired_token(auth, rsa_keys):
    user_id = random_user_id()
    access_token = create_access_token({"user_id": user_id}, rsa_keys.private_pem, expires_in=timedelta(minutes=-5))
    with pytest.raises(UnauthorizedException):
        auth.validate_access_token_and_get_user("Bearer " + access_token)


def test_validate_with_bad_issuer(auth, rsa_keys):
    user_id = random_user_id()
    access_token = create_access_token({"user_id": user_id}, rsa_keys.private_pem, issuer=HTTP_BASE_AUTH_URL)
    with pytest.raises(UnauthorizedException):
        auth.validate_access_token_and_get_user("Bearer " + access_token)


def test_validate_with_wrong_key(auth, rsa_keys):
    incorrect_rsa_keys = generate_rsa_keys()

    user_id = random_user_id()
    access_token = create_access_token({"user_id": user_id}, incorrect_rsa_keys.private_pem)
    with pytest.raises(UnauthorizedException):
        auth.validate_access_token_and_get_user("Bearer " + access_token)
