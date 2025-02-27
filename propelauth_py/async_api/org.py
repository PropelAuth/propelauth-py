from typing import Optional, Dict, Any, List
import aiohttp

from propelauth_py.api import UserNotFoundException, BadRequestException, OrgNotFoundException
from propelauth_py.types.custom_role_mappings import CustomRoleMapping
from propelauth_py.types.saml_types import SamlIdpMetadata, SamlSpMetadata
from propelauth_py.errors import RateLimitedException


class OrgResponse:
    def __init__(self, org_id: str, name: str):
        self.org_id = org_id
        self.name = name


async def _fetch_org(auth_url, integration_api_key, org_id, session=None):
    from propelauth_py.async_api.user import _is_valid_id
    if not _is_valid_id(org_id):
        raise OrgNotFoundException()

    url = auth_url + f"/api/orgs/{org_id}"
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_fetch_org(session, url, headers)
    else:
        return await _do_fetch_org(session, url, headers)


async def _do_fetch_org(session, url, headers):
    async with session.get(url, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            text = await response.text()
            raise ValueError("Bad request: " + text)
        elif response.status == 404:
            raise OrgNotFoundException()
        elif not response.ok:
            raise RuntimeError("Unknown error when fetching org")

        json_response = await response.json()
        return {
            "org_id": json_response.get('org_id'),
            "name": json_response.get('name'),
            "metadata": json_response.get('metadata'),
            "max_users": json_response.get('max_users'),
            "can_join_on_email_domain_match": json_response.get('can_join_on_email_domain_match'),
            "members_must_have_email_domain_match": json_response.get('members_must_have_email_domain_match'),
            "domain": json_response.get('domain'),
            "can_setup_saml": json_response.get('can_setup_saml'),
            "has_saml_connection": json_response.get('has_saml_connection'),
            "use_saml_over_oidc": json_response.get('use_saml_over_oidc'),
            "saml_connection_testing_status": json_response.get('saml_connection_testing_status'),
            "saml_connection_live_status": json_response.get('saml_connection_live_status'),
            "saml_error_message": json_response.get('saml_error_message'),
            "saml_external_id": json_response.get('saml_external_id')
        }


async def _fetch_org_by_query(
    auth_url,
    integration_api_key,
    page_size=10,
    page_number=0,
    order_by=None,
    name=None,
    legacy_org_id=None,
    domain=None,
    session=None
):
    url = auth_url + "/api/orgs/query"
    json_body = {
        "page_size": page_size,
        "page_number": page_number,
        "order_by": order_by.value if order_by else None,
        "name": name,
        "legacy_org_id": legacy_org_id,
        "domain": domain
    }
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_fetch_org_by_query(session, url, headers, json_body)
    else:
        return await _do_fetch_org_by_query(session, url, headers, json_body)


async def _do_fetch_org_by_query(session, url, headers, json_body):
    async with session.post(url, json={k: v for k, v in json_body.items() if v is not None}, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            text = await response.text()
            raise ValueError("Bad request: " + text)
        elif not response.ok:
            raise RuntimeError("Unknown error when fetching orgs by query")

        json_response = await response.json()
        total_orgs = json_response.get('total_orgs', 0)
        current_page = json_response.get('current_page', 0)
        page_size = json_response.get('page_size', 0)
        has_more_results = json_response.get('has_more_results', False)
        orgs = json_response.get('orgs', [])

        return {
            "total_orgs": total_orgs,
            "current_page": current_page,
            "page_size": page_size,
            "has_more_results": has_more_results,
            "orgs": orgs
        }


async def _fetch_custom_role_mappings(auth_url, integration_api_key, session=None):
    url = auth_url + "/api/custom_role_mappings"
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_fetch_custom_role_mappings(session, url, headers)
    else:
        return await _do_fetch_custom_role_mappings(session, url, headers)


async def _do_fetch_custom_role_mappings(session, url, headers):
    async with session.get(url, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            text = await response.text()
            raise ValueError("Bad request: " + text)
        elif not response.ok:
            raise RuntimeError("Unknown error when fetching custom role mappings")

        json_response = await response.json()
        mappings = json_response.get('mappings', [])
        
        return [
            CustomRoleMapping(
                mapping_name=mapping.get('mapping_name'),
                mapping_type=mapping.get('mapping_type'),
                roles=mapping.get('roles', [])
            )
            for mapping in mappings
        ]


async def _fetch_pending_invites(
    auth_url,
    integration_api_key,
    page_number=0,
    page_size=10,
    org_id=None,
    session=None
):
    url = auth_url + "/api/invites"
    query = {
        "page_number": page_number,
        "page_size": page_size,
        "org_id": org_id
    }
    
    from propelauth_py.async_api.user import _format_params
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_fetch_pending_invites(session, url, headers, query)
    else:
        return await _do_fetch_pending_invites(session, url, headers, query)


async def _do_fetch_pending_invites(session, url, headers, query):
    async with session.get(url, params=query, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            text = await response.text()
            raise ValueError("Bad request: " + text)
        elif not response.ok:
            raise RuntimeError("Unknown error when fetching pending invites")

        json_response = await response.json()
        total_invites = json_response.get('total_invites', 0)
        current_page = json_response.get('current_page', 0)
        page_size = json_response.get('page_size', 0)
        has_more_results = json_response.get('has_more_results', False)
        invites = json_response.get('invites', [])

        return {
            "total_invites": total_invites,
            "current_page": current_page,
            "page_size": page_size,
            "has_more_results": has_more_results,
            "invites": invites
        }


async def _create_org(
    auth_url,
    integration_api_key,
    name,
    enable_auto_joining_by_domain=False,
    members_must_have_matching_domain=False,
    domain=None,
    max_users=None,
    custom_role_mapping_name=None,
    legacy_org_id=None,
    session=None
) -> OrgResponse:
    url = auth_url + "/api/orgs"
    json_body = {
        "name": name,
        "enable_auto_joining_by_domain": enable_auto_joining_by_domain,
        "members_must_have_matching_domain": members_must_have_matching_domain,
        "domain": domain,
        "max_users": max_users,
        "custom_role_mapping_name": custom_role_mapping_name,
        "legacy_org_id": legacy_org_id
    }
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_create_org(session, url, headers, json_body)
    else:
        return await _do_create_org(session, url, headers, json_body)


async def _do_create_org(session, url, headers, json_body):
    async with session.post(url, json={k: v for k, v in json_body.items() if v is not None}, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            json_data = await response.json()
            raise BadRequestException(json_data)
        elif not response.ok:
            raise RuntimeError("Unknown error when creating org")

        json_response = await response.json()
        return OrgResponse(
            org_id=json_response.get('org_id'),
            name=json_response.get('name')
        )


async def _update_org_metadata(
    auth_url,
    integration_api_key,
    org_id,
    name=None,
    can_setup_saml=None,
    metadata=None,
    max_users=None,
    can_join_on_email_domain_match=None,
    members_must_have_email_domain_match=None,
    domain=None,
    session=None
):
    from propelauth_py.async_api.user import _is_valid_id
    if not _is_valid_id(org_id):
        raise OrgNotFoundException()

    url = auth_url + f"/api/orgs/{org_id}"
    json_body = {
        "name": name,
        "can_setup_saml": can_setup_saml,
        "metadata": metadata,
        "max_users": max_users,
        "can_join_on_email_domain_match": can_join_on_email_domain_match,
        "members_must_have_email_domain_match": members_must_have_email_domain_match,
        "domain": domain
    }
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_update_org_metadata(session, url, headers, json_body)
    else:
        return await _do_update_org_metadata(session, url, headers, json_body)


async def _do_update_org_metadata(session, url, headers, json_body):
    async with session.put(url, json={k: v for k, v in json_body.items() if v is not None}, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            json_data = await response.json()
            raise BadRequestException(json_data)
        elif response.status == 404:
            raise OrgNotFoundException()
        elif not response.ok:
            raise RuntimeError("Unknown error when updating org metadata")

        return True


async def _subscribe_org_to_role_mapping(auth_url, integration_api_key, org_id, custom_role_mapping_name, session=None):
    from propelauth_py.async_api.user import _is_valid_id
    if not _is_valid_id(org_id):
        raise OrgNotFoundException()

    url = auth_url + f"/api/orgs/{org_id}/subscribe_to_role_mapping"
    json_body = {
        "custom_role_mapping_name": custom_role_mapping_name
    }
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_subscribe_org_to_role_mapping(session, url, headers, json_body)
    else:
        return await _do_subscribe_org_to_role_mapping(session, url, headers, json_body)


async def _do_subscribe_org_to_role_mapping(session, url, headers, json_body):
    async with session.post(url, json=json_body, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            json_data = await response.json()
            raise BadRequestException(json_data)
        elif response.status == 404:
            raise OrgNotFoundException()
        elif not response.ok:
            raise RuntimeError("Unknown error when subscribing org to role mapping")

        return True


async def _delete_org(auth_url, integration_api_key, org_id, session=None):
    from propelauth_py.async_api.user import _is_valid_id
    if not _is_valid_id(org_id):
        raise OrgNotFoundException()

    url = auth_url + f"/api/orgs/{org_id}"
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_delete_org(session, url, headers)
    else:
        return await _do_delete_org(session, url, headers)


async def _do_delete_org(session, url, headers):
    async with session.delete(url, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            text = await response.text()
            raise ValueError("Bad request: " + text)
        elif response.status == 404:
            raise OrgNotFoundException()
        elif not response.ok:
            raise RuntimeError("Unknown error when deleting org")

        return True


async def _add_user_to_org(auth_url, integration_api_key, user_id, org_id, role, additional_roles=[], session=None):
    from propelauth_py.async_api.user import _is_valid_id
    if not _is_valid_id(user_id):
        raise UserNotFoundException()
    if not _is_valid_id(org_id):
        raise OrgNotFoundException()

    url = auth_url + f"/api/orgs/{org_id}/users/{user_id}"
    json_body = {
        "role": role,
        "additional_roles": additional_roles
    }
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_add_user_to_org(session, url, headers, json_body)
    else:
        return await _do_add_user_to_org(session, url, headers, json_body)


async def _do_add_user_to_org(session, url, headers, json_body):
    async with session.post(url, json=json_body, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            json_data = await response.json()
            raise BadRequestException(json_data)
        elif response.status == 404:
            raise UserNotFoundException()
        elif not response.ok:
            raise RuntimeError("Unknown error when adding user to org")

        return True


async def _remove_user_from_org(auth_url, integration_api_key, user_id, org_id, session=None):
    from propelauth_py.async_api.user import _is_valid_id
    if not _is_valid_id(user_id):
        raise UserNotFoundException()
    if not _is_valid_id(org_id):
        raise OrgNotFoundException()

    url = auth_url + f"/api/orgs/{org_id}/users/{user_id}"
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_remove_user_from_org(session, url, headers)
    else:
        return await _do_remove_user_from_org(session, url, headers)


async def _do_remove_user_from_org(session, url, headers):
    async with session.delete(url, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            text = await response.text()
            raise ValueError("Bad request: " + text)
        elif response.status == 404:
            raise UserNotFoundException()
        elif not response.ok:
            raise RuntimeError("Unknown error when removing user from org")

        return True


async def _change_user_role_in_org(auth_url, integration_api_key, user_id, org_id, role, additional_roles=[], session=None):
    from propelauth_py.async_api.user import _is_valid_id
    if not _is_valid_id(user_id):
        raise UserNotFoundException()
    if not _is_valid_id(org_id):
        raise OrgNotFoundException()

    url = auth_url + f"/api/orgs/{org_id}/users/{user_id}"
    json_body = {
        "role": role,
        "additional_roles": additional_roles
    }
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_change_user_role_in_org(session, url, headers, json_body)
    else:
        return await _do_change_user_role_in_org(session, url, headers, json_body)


async def _do_change_user_role_in_org(session, url, headers, json_body):
    async with session.put(url, json=json_body, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            json_data = await response.json()
            raise BadRequestException(json_data)
        elif response.status == 404:
            raise UserNotFoundException()
        elif not response.ok:
            raise RuntimeError("Unknown error when changing user role in org")

        return True


async def _allow_org_to_setup_saml_connection(auth_url, integration_api_key, org_id, session=None):
    from propelauth_py.async_api.user import _is_valid_id
    if not _is_valid_id(org_id):
        raise OrgNotFoundException()

    url = auth_url + f"/api/orgs/{org_id}/setup_saml/allow"
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_allow_org_to_setup_saml_connection(session, url, headers)
    else:
        return await _do_allow_org_to_setup_saml_connection(session, url, headers)


async def _do_allow_org_to_setup_saml_connection(session, url, headers):
    async with session.post(url, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            text = await response.text()
            raise ValueError("Bad request: " + text)
        elif response.status == 404:
            raise OrgNotFoundException()
        elif not response.ok:
            raise RuntimeError("Unknown error when allowing org to setup SAML connection")

        return True


async def _disallow_org_to_setup_saml_connection(auth_url, integration_api_key, org_id, session=None):
    from propelauth_py.async_api.user import _is_valid_id
    if not _is_valid_id(org_id):
        raise OrgNotFoundException()

    url = auth_url + f"/api/orgs/{org_id}/setup_saml/disallow"
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_disallow_org_to_setup_saml_connection(session, url, headers)
    else:
        return await _do_disallow_org_to_setup_saml_connection(session, url, headers)


async def _do_disallow_org_to_setup_saml_connection(session, url, headers):
    async with session.post(url, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            text = await response.text()
            raise ValueError("Bad request: " + text)
        elif response.status == 404:
            raise OrgNotFoundException()
        elif not response.ok:
            raise RuntimeError("Unknown error when disallowing org to setup SAML connection")

        return True


async def _create_org_saml_connection_link(auth_url, integration_api_key, org_id, expires_in_seconds=None, session=None):
    from propelauth_py.async_api.user import _is_valid_id
    if not _is_valid_id(org_id):
        raise OrgNotFoundException()

    url = auth_url + f"/api/orgs/{org_id}/setup_saml/create_link"
    
    json_body = {}
    if expires_in_seconds is not None:
        json_body["expires_in_seconds"] = expires_in_seconds
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_create_org_saml_connection_link(session, url, headers, json_body)
    else:
        return await _do_create_org_saml_connection_link(session, url, headers, json_body)


async def _do_create_org_saml_connection_link(session, url, headers, json_body):
    async with session.post(url, json=json_body, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            text = await response.text()
            raise ValueError("Bad request: " + text)
        elif response.status == 404:
            raise OrgNotFoundException()
        elif not response.ok:
            raise RuntimeError("Unknown error when creating org SAML connection link")

        json_response = await response.json()
        return {
            "url": json_response.get("url")
        }


async def _revoke_pending_org_invite(auth_url, integration_api_key, org_id, invitee_email, session=None):
    from propelauth_py.async_api.user import _is_valid_id
    if not _is_valid_id(org_id):
        raise OrgNotFoundException()

    url = auth_url + f"/api/orgs/{org_id}/invites"
    json_body = {
        "email": invitee_email
    }
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_revoke_pending_org_invite(session, url, headers, json_body)
    else:
        return await _do_revoke_pending_org_invite(session, url, headers, json_body)


async def _do_revoke_pending_org_invite(session, url, headers, json_body):
    async with session.delete(url, json=json_body, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            text = await response.text()
            raise ValueError("Bad request: " + text)
        elif response.status == 404:
            raise OrgNotFoundException()
        elif not response.ok:
            raise RuntimeError("Unknown error when revoking pending org invite")

        return True


async def _fetch_saml_sp_metadata(
    auth_url,
    integration_api_key,
    org_id,
    session=None
) -> SamlSpMetadata:
    from propelauth_py.async_api.user import _is_valid_id
    if not _is_valid_id(org_id):
        raise OrgNotFoundException()

    url = auth_url + f"/api/saml/orgs/{org_id}/sp_metadata"
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_fetch_saml_sp_metadata(session, url, headers)
    else:
        return await _do_fetch_saml_sp_metadata(session, url, headers)


async def _do_fetch_saml_sp_metadata(session, url, headers):
    async with session.get(url, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            text = await response.text()
            raise ValueError("Bad request: " + text)
        elif response.status == 404:
            raise OrgNotFoundException()
        elif not response.ok:
            raise RuntimeError("Unknown error when fetching SAML SP metadata")

        json_response = await response.json()
        return SamlSpMetadata(
            acs_url=json_response.get('acs_url'),
            entity_id=json_response.get('entity_id'),
            metadata_endpoint=json_response.get('metadata_endpoint')
        )


async def _set_saml_idp_metadata(
    auth_url,
    integration_api_key,
    org_id,
    saml_idp_metadata: SamlIdpMetadata,
    session=None
):
    from propelauth_py.async_api.user import _is_valid_id
    if not _is_valid_id(org_id):
        raise OrgNotFoundException()

    url = auth_url + f"/api/saml/orgs/{org_id}/idp_metadata"
    
    json_body = {
        "idp_entity_id": saml_idp_metadata.idp_entity_id,
        "idp_sso_url": saml_idp_metadata.idp_sso_url,
        "idp_certificate": saml_idp_metadata.idp_certificate,
        "sp_initiated_login_path": saml_idp_metadata.sp_initiated_login_path,
        "allow_idp_initiated": saml_idp_metadata.allow_idp_initiated,
    }
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_set_saml_idp_metadata(session, url, headers, json_body)
    else:
        return await _do_set_saml_idp_metadata(session, url, headers, json_body)


async def _do_set_saml_idp_metadata(session, url, headers, json_body):
    async with session.post(url, json={k: v for k, v in json_body.items() if v is not None}, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            json_data = await response.json()
            raise BadRequestException(json_data)
        elif response.status == 404:
            raise OrgNotFoundException()
        elif not response.ok:
            raise RuntimeError("Unknown error when setting SAML IDP metadata")

        return True


async def _saml_go_live(
    auth_url,
    integration_api_key,
    org_id,
    session=None
):
    from propelauth_py.async_api.user import _is_valid_id
    if not _is_valid_id(org_id):
        raise OrgNotFoundException()

    url = auth_url + f"/api/saml/orgs/{org_id}/go_live"
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_saml_go_live(session, url, headers)
    else:
        return await _do_saml_go_live(session, url, headers)


async def _do_saml_go_live(session, url, headers):
    async with session.post(url, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            json_data = await response.json()
            raise BadRequestException(json_data)
        elif response.status == 404:
            raise OrgNotFoundException()
        elif not response.ok:
            raise RuntimeError("Unknown error when setting SAML go live")

        return True


async def _delete_saml_connection(
    auth_url,
    integration_api_key,
    org_id,
    session=None
):
    from propelauth_py.async_api.user import _is_valid_id
    if not _is_valid_id(org_id):
        raise OrgNotFoundException()

    url = auth_url + f"/api/saml/orgs/{org_id}"
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_delete_saml_connection(session, url, headers)
    else:
        return await _do_delete_saml_connection(session, url, headers)


async def _do_delete_saml_connection(session, url, headers):
    async with session.delete(url, headers=headers) as response:
        if response.status == 401:
            raise ValueError("integration_api_key is incorrect")
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            json_data = await response.json()
            raise BadRequestException(json_data)
        elif response.status == 404:
            raise OrgNotFoundException()
        elif not response.ok:
            raise RuntimeError("Unknown error when deleting SAML connection")

        return True


async def _validate_org_api_key(auth_url, integration_api_key, api_key_token, session=None):
    url = auth_url + "/api/backend/org_api_key/validate_api_key"
    json_body = {"api_key_token": api_key_token}
    
    headers = {"Authorization": f"Bearer {integration_api_key}"}
    
    if session is None:
        async with aiohttp.ClientSession() as session:
            return await _do_validate_org_api_key(session, url, headers, json_body)
    else:
        return await _do_validate_org_api_key(session, url, headers, json_body)


async def _do_validate_org_api_key(session, url, headers, json_body):
    async with session.post(url, json=json_body, headers=headers) as response:
        if response.status == 401:
            return None
        elif response.status == 429:
            text = await response.text()
            raise RateLimitedException(text)
        elif response.status == 400:
            text = await response.text()
            raise ValueError("Bad request: " + text)
        elif not response.ok:
            raise RuntimeError("Unknown error when validating org API key")

        json_response = await response.json()
        return {
            "org_id": json_response.get('org_id'),
            "org_name": json_response.get('org_name')
        }