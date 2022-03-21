from collections import namedtuple

import pytest
import requests_mock
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

from propelauth_py import init_base_auth

TestRsaKeys = namedtuple("TestRsaKeys", ["public_pem", "private_pem"])

BASE_AUTH_URL = "https://test.propelauth.com"
HTTP_BASE_AUTH_URL = "http://test.propelauth.com"


@pytest.fixture(scope='function')
def rsa_keys():
    return generate_rsa_keys()


def generate_rsa_keys():
    private_key = generate_private_key(public_exponent=65537, key_size=2048)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    return TestRsaKeys(public_pem=public_key_pem, private_pem=private_key_pem)


@pytest.fixture(scope='function')
def auth(rsa_keys):
    return mock_api_and_init_auth(BASE_AUTH_URL, 200, {
        "verifier_key_pem": rsa_keys.public_pem,
        "roles": [{"name": "Owner"}, {"name": "Admin"}, {"name": "Member"}]
    })


def mock_api_and_init_auth(auth_url, status_code, json):
    with requests_mock.Mocker() as m:
        api_key = "api_key"
        m.get(BASE_AUTH_URL + "/api/v1/token_verification_metadata",
              request_headers={'Authorization': 'Bearer ' + api_key},
              json=json,
              status_code=status_code)
        return init_base_auth(auth_url, api_key)
