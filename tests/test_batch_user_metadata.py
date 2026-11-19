"""Batch lookups must expose the same user metadata interface as single lookups."""

import asyncio
import json

import httpx
import pytest
import requests_mock

from propelauth_py import init_base_async_auth, init_base_auth
from propelauth_py.api import BACKEND_API_BASE_URL, TokenVerificationMetadata


USER = {
    "user_id": "00000000-0000-4000-8000-000000000001",
    "email": "synthetic@example.invalid",
    "username": "synthetic-user",
    "email_confirmed": True,
    "has_password": False,
    "enabled": True,
    "locked": False,
    "mfa_enabled": False,
    "can_create_orgs": False,
    "created_at": 1,
    "last_active_at": 2,
    "metadata": {"source": "test"},
    "properties": {"display": "Synthetic"},
}
ORG = {
    "org_id": "synthetic-org",
    "org_name": "Synthetic",
    "org_metadata": {},
    "user_role": "Member",
    "url_safe_org_name": "synthetic",
    "inherited_user_roles_plus_current_role": ["Member"],
    "user_permissions": ["read:example"],
}
LOOKUPS = [("user_ids", "user_id"), ("emails", "email"), ("usernames", "username")]


@pytest.mark.parametrize("lookup,key", LOOKUPS)
@pytest.mark.parametrize("include_orgs", [False, True])
@pytest.mark.parametrize("empty", [False, True])
@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
def test_batch_metadata_interface(lookup, key, include_orgs, empty, asynchronous):
    record = dict(
        USER, org_id_to_org_info={"synthetic-org": ORG} if include_orgs else None
    )
    payload = [] if empty else [record]
    identifiers = [USER[key]]
    metadata = TokenVerificationMetadata(
        verifier_key="unused", issuer="https://example.invalid"
    )
    url = f"{BACKEND_API_BASE_URL}/api/backend/v1/user/{lookup}"
    captured = []

    if asynchronous:

        def handle(request):
            captured.append(request)
            return httpx.Response(200, json=payload)

        async def execute():
            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handle)
            ) as transport:
                auth = init_base_async_auth(
                    "https://example.invalid", "synthetic-key", metadata, transport
                )
                return await getattr(auth, "fetch_batch_user_metadata_by_" + lookup)(
                    identifiers, include_orgs=include_orgs
                )

        result = asyncio.run(execute())
        request = captured[0]
        assert dict(request.url.params) == {"include_orgs": str(include_orgs).lower()}
        assert json.loads(request.content) == {lookup: identifiers}
        headers = request.headers
    else:
        auth = init_base_auth("https://example.invalid", "synthetic-key", metadata)
        with requests_mock.Mocker() as transport:
            transport.post(url, json=payload)
            result = getattr(auth, "fetch_batch_user_metadata_by_" + lookup)(
                identifiers, include_orgs=include_orgs
            )
            request = transport.last_request
            assert request.qs == {"include_orgs": [str(include_orgs).lower()]}
            assert request.json() == {lookup: identifiers}
            headers = request.headers
    assert headers["Authorization"] == "Bearer synthetic-key"
    assert headers["X-Propelauth-url"] == "example.invalid"
    if empty:
        assert result == {}
        return
    assert list(result) == identifiers
    user = result[identifiers[0]]
    assert user.email == USER["email"]
    assert user["user_id"] == USER["user_id"]
    assert user.metadata == USER["metadata"]
    assert user.properties == USER["properties"]
    if include_orgs:
        member = user.org_id_to_org_info["synthetic-org"]
        assert member.user_is_role("Member")
        assert member.user_has_permission("read:example")
    else:
        assert user.org_id_to_org_info is None
