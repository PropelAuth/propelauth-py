from datetime import timezone, datetime, timedelta
from uuid import uuid4

import jwt

from tests.conftest import TEST_BASE_AUTH_URL
from propelauth_py.validation import _validate_and_extract_auth_hostname


def create_access_token(user, private_key_pem, issuer=TEST_BASE_AUTH_URL, expires_in=timedelta(minutes=30)):
    payload = user.copy()
    now = datetime.now(tz=timezone.utc)
    payload["iat"] = now
    payload["exp"] = now + expires_in
    payload["iss"] = "https://" + _validate_and_extract_auth_hostname(issuer)
    return jwt.encode(payload, private_key_pem, algorithm="RS256")


def random_user_id():
    return str(uuid4())


def random_org_id():
    return str(uuid4())


def random_org(user_role_str, permissions=None):
    # represents the incoming JSON from the auth server
    return {
        "org_id": random_org_id(),
        "org_name": str(uuid4()),
        "org_metadata": {},
        "user_role": user_role_str,
        "inherited_user_roles_plus_current_role": [user_role_str],
        "user_permissions": [] if permissions is None else permissions,
        "org_role_structure": "single_role_in_hierarchy",
        "url_safe_org_name": str(uuid4()),
        "additional_roles": [],
    }


def orgs_to_org_id_map(orgs):
    org_id_to_org_member_info = {}
    for org in orgs:
        org_id_to_org_member_info[org["org_id"]] = org
    return org_id_to_org_member_info