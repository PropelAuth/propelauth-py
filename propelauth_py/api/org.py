from typing import Optional
import requests

from propelauth_py.api import _ApiKeyAuth, _format_params, _is_valid_id, _auth_hostname_header, BACKEND_API_BASE_URL
from propelauth_py.api.end_user_api_keys import _validate_api_key
from propelauth_py.types.user import Organization, OrgQueryResponse, Org, PendingInvite, PendingInvitesPage, CreatedOrg, OrgApiKeyValidation
from propelauth_py.types.custom_role_mappings import CustomRoleMappings, CustomRoleMapping
from propelauth_py.types.saml_types import SamlIdpMetadata, SpMetadata
from propelauth_py.errors import (
    BadRequestException,
    EndUserApiKeyException,
    UpdateUserMetadataException,
    RateLimitedException,
)

BASE_ENDPOINT_URL = f"{BACKEND_API_BASE_URL}/api/backend/v1"
ORG_ENDPOINT_URL = f"{BACKEND_API_BASE_URL}/api/backend/v1/org"


####################
#       GET        #
####################
def _fetch_org(auth_hostname, integration_api_key, org_id) -> Optional[Organization]:
    if not _is_valid_id(org_id):
        return None

    url = f"{ORG_ENDPOINT_URL}/{org_id}"

    response = requests.get(
        url,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 404:
        return None
    elif response.status_code == 426:
        raise RuntimeError(
            "Cannot use organizations unless B2B support is enabled. Enable it in your PropelAuth "
            "dashboard."
        )
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching org")

    json_response = response.json()
    return Organization(
        org_id=json_response.get('org_id'),
        name=json_response.get('name'),
        url_safe_org_slug=json_response.get('url_safe_org_slug'),
        can_setup_saml=json_response.get('can_setup_saml'),
        is_saml_configured=json_response.get('is_saml_configured'),
        is_saml_in_test_mode=json_response.get('is_saml_in_test_mode'),
        max_users=json_response.get('max_users'),
        metadata=json_response.get('metadata'),
        domain=json_response.get('domain'),
        extra_domains=json_response.get('extra_domains'),
        domain_autojoin=json_response.get('domain_autojoin'),
        domain_restrict=json_response.get('domain_restrict'),
        custom_role_mapping_name=json_response.get('custom_role_mapping_name'),
        legacy_org_id=json_response.get('legacy_org_id')
    )


def _fetch_org_by_query(
    auth_hostname, integration_api_key, page_size, page_number, order_by, name, legacy_org_id, domain
) -> OrgQueryResponse:
    url = f"{ORG_ENDPOINT_URL}/query"
    params = {
        "page_size": page_size,
        "page_number": page_number,
        "order_by": order_by,
        "name": name,
        "legacy_org_id": legacy_org_id,
        "domain": domain,
    }
    response = requests.get(
        url,
        params=_format_params(params),
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise ValueError("Bad request: " + response.text)
    elif response.status_code == 426:
        raise RuntimeError(
            "Cannot use organizations unless B2B support is enabled. Enable it in your PropelAuth "
            "dashboard."
        )
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching orgs by query")

    json_response = response.json()
    
    orgs = [
        Org(
            org_id=key.get('org_id'),
            name=key.get('name'),
            max_users=key.get('max_users'),
            is_saml_configured=key.get('is_saml_configured'),
            legacy_org_id=key.get('legacy_org_id'),
            metadata=key.get('metadata'),
            custom_role_mapping_name=key.get('custom_role_mapping_name')
        )
        for key in json_response.get('orgs')
    ]
    
    return OrgQueryResponse(
        orgs=orgs,
        total_orgs=json_response.get('total_orgs'),
        current_page=json_response.get('current_page'),
        page_size=json_response.get('page_size'),
        has_more_results=json_response.get('has_more_results')
    )


def _fetch_custom_role_mappings(auth_hostname, integration_api_key) -> CustomRoleMappings:
    url = BASE_ENDPOINT_URL + "/custom_role_mappings"

    response = requests.get(
        url,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 426:
        raise RuntimeError(
            "Cannot use organizations unless B2B support is enabled. Enable it in your PropelAuth "
            "dashboard."
        )
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching org")

    json_response = response.json()
    
    role_mappings = [
        CustomRoleMapping(
            custom_role_mapping_name=key.get('custom_role_mapping_name'),
            num_orgs_subscribed=key.get('num_orgs_subscribed')
        )
        for key in json_response.get('custom_role_mappings')
    ]
    
    return CustomRoleMappings(
        custom_role_mappings=role_mappings
    )


def _fetch_pending_invites(
    auth_hostname,
    integration_api_key,
    page_number=0,
    page_size=10,
    org_id=None,
) -> Optional[PendingInvitesPage]:
    if org_id:
        if not _is_valid_id(org_id):
            return None

    url = BASE_ENDPOINT_URL + "/pending_org_invites"
    params = {
        "page_number": page_number,
        "page_size": page_size,
        "org_id": org_id,
    }

    response = requests.get(
        url,
        params=_format_params(params),
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 426:
        raise RuntimeError(
            "Cannot use organizations unless B2B support is enabled. Enable it in your PropelAuth "
            "dashboard."
        )
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching pending invites")

    json_response = response.json()
    
    invites = [
        PendingInvite(
            invitee_email=key.get('invitee_email'),
            org_id=key.get('org_id'),
            org_name=key.get('org_name'),
            role_in_org=key.get('role_in_org'),
            additional_roles_in_org=key.get('additional_roles_in_org'),
            created_at=key.get('created_at'),
            expires_at=key.get('expires_at'),
            inviter_email=key.get('inviter_email'),
            inviter_user_id=key.get('inviter_user_id'),
        )
        for key in json_response.get('invites')
    ]
    
    return PendingInvitesPage(
        invites=invites,
        total_invites=json_response.get('total_invites'),
        current_page=json_response.get('current_page'),
        page_size=json_response.get('page_size'),
        has_more_results=json_response.get('has_more_results')
    )
    
def _fetch_saml_sp_metadata(auth_hostname, integration_api_key, org_id) -> Optional[SpMetadata]:
    if not _is_valid_id(org_id):
        return None

    url = f"{BASE_ENDPOINT_URL}/saml_sp_metadata/{org_id}"

    response = requests.get(
        url,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 404:
        return None
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching org SAML SP metadata")

    json_response = response.json()
    return SpMetadata(
        entity_id=json_response.get('entity_id'),
        acs_url=json_response.get('acs_url'),
        logout_url=json_response.get('logout_url'),
    )


####################
#       POST       #
####################
def _create_org(
    auth_hostname,
    integration_api_key,
    name,
    enable_auto_joining_by_domain=False,
    members_must_have_matching_domain=False,
    domain=None,
    max_users=None,
    custom_role_mapping_name=None,
    legacy_org_id=None,
) -> CreatedOrg:
    url = f"{ORG_ENDPOINT_URL}/"
    json = {
        "name": name,
        "enable_auto_joining_by_domain": enable_auto_joining_by_domain,
        "members_must_have_matching_domain": members_must_have_matching_domain,
    }
    if domain:
        json["domain"] = domain
    if max_users is not None:
        json["max_users"] = max_users
    if legacy_org_id:
        json["legacy_org_id"] = legacy_org_id
    if custom_role_mapping_name is not None:
        json["custom_role_mapping_name"] = custom_role_mapping_name

    response = requests.post(
        url,
        json=json,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif not response.ok:
        raise RuntimeError("Unknown error when creating an org")

    json_response = response.json()
    return CreatedOrg(
        org_id=json_response.get('org_id'),
        name=json_response.get('name')
    )


def _allow_org_to_setup_saml_connection(auth_hostname, integration_api_key, org_id) -> bool:
    if not _is_valid_id(org_id):
        return False

    url = f"{ORG_ENDPOINT_URL}/{org_id}/allow_saml"

    response = requests.post(
        url,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when allowing org to setup SAML connection")

    return True


def _disallow_org_to_setup_saml_connection(auth_hostname, integration_api_key, org_id) -> bool:
    if not _is_valid_id(org_id):
        return False

    url = f"{ORG_ENDPOINT_URL}/{org_id}/disallow_saml"

    response = requests.post(
        url,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when allowing org to setup SAML connection")

    return True


def _create_org_saml_connection_link(
    auth_hostname, integration_api_key, org_id, expires_in_seconds=None
):
    if not _is_valid_id(org_id):
        return None

    url = f"{ORG_ENDPOINT_URL}/{org_id}/create_saml_connection_link"

    body = {}
    if expires_in_seconds is not None:
        body["expires_in_seconds"] = expires_in_seconds

    response = requests.post(
        url,
        json=body,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif response.status_code == 426:
        raise RuntimeError(
            "Cannot use organizations unless B2B support is enabled. Enable it in your PropelAuth "
            "dashboard."
        )
    elif not response.ok:
        raise RuntimeError("Unknown error when creating org SAML connection link")

    return response.json()


def _add_user_to_org(
    auth_hostname, integration_api_key, user_id, org_id, role, additional_roles=[]
) -> bool:
    url = f"{ORG_ENDPOINT_URL}/add_user"
    json = {
        "user_id": user_id,
        "org_id": org_id,
        "role": role,
        "additional_roles": additional_roles,
    }

    response = requests.post(
        url,
        json=json,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when adding a user to the org")

    return True


def _remove_user_from_org(auth_hostname, integration_api_key, user_id, org_id) -> bool:
    url = f"{ORG_ENDPOINT_URL}/remove_user"
    json = {"user_id": user_id, "org_id": org_id}

    response = requests.post(
        url,
        json=json,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when removing a user from the org")

    return True


def _change_user_role_in_org(
    auth_hostname, integration_api_key, user_id, org_id, role, additional_roles=[]
) -> bool:
    url = f"{ORG_ENDPOINT_URL}/change_role"
    json = {
        "user_id": user_id,
        "org_id": org_id,
        "role": role,
        "additional_roles": additional_roles,
    }

    response = requests.post(
        url,
        json=json,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when changing a user's role(s) in the org")

    return True

def _set_saml_idp_metadata(auth_hostname, integration_api_key, org_id, saml_idp_metadata: SamlIdpMetadata) -> bool:
    if not _is_valid_id(org_id):
        return False

    url = f"{BASE_ENDPOINT_URL}/saml_idp_metadata"

    required_fields = ["idp_entity_id", "idp_sso_url", "idp_certificate", "provider"]
    json = {"org_id": org_id}
    
    for field in required_fields:
        if field not in saml_idp_metadata:
            raise ValueError(f"Missing required field '{field}' in SAML IdP metadata")
        json[field] = saml_idp_metadata[field]

    response = requests.post(
        url,
        json=json,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when setting SAML IdP metadata")

    return True

def _saml_go_live(auth_hostname, integration_api_key, org_id) -> bool:
    if not _is_valid_id(org_id):
        return False

    url = f"{BASE_ENDPOINT_URL}/saml_idp_metadata/go_live/{org_id}"

    response = requests.post(
        url,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when setting SAML connection to go live")

    return True

####################
#     PATCH/PUT    #
####################
def _update_org_metadata(
    auth_hostname,
    integration_api_key,
    org_id,
    name=None,
    can_setup_saml=None,
    metadata=None,
    max_users=None,
    can_join_on_email_domain_match=None,  # In the backend, this is the `domain_autojoin` argument.
    members_must_have_email_domain_match=None,  # In the backend, this is the `domain_restrict` argument.
    domain=None,
    legacy_org_id=None,
    require_2fa_by=None,
    extra_domains=None,
) -> bool:
    if not _is_valid_id(org_id):
        return False

    url = f"{ORG_ENDPOINT_URL}/{org_id}"
    json = {}
    if name is not None:
        json["name"] = name
    if can_setup_saml is not None:
        json["can_setup_saml"] = can_setup_saml
    if metadata is not None:
        json["metadata"] = metadata
    if max_users is not None:
        json["max_users"] = max_users
    if can_join_on_email_domain_match is not None:
        json["autojoin_by_domain"] = can_join_on_email_domain_match
    if members_must_have_email_domain_match is not None:
        json["restrict_to_domain"] = members_must_have_email_domain_match
    if domain is not None:
        json["domain"] = domain
    if legacy_org_id is not None:
        json["legacy_org_id"] = legacy_org_id
    if require_2fa_by is not None:
        json["require_2fa_by"] = require_2fa_by
    if extra_domains is not None:
        json["extra_domains"] = extra_domains

    response = requests.put(
        url,
        json=json,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise UpdateUserMetadataException(response.json())
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when updating org metadata")

    return True


def _subscribe_org_to_role_mapping(
    auth_hostname,
    integration_api_key,
    org_id,
    custom_role_mapping_name,
) -> bool:
    if not _is_valid_id(org_id):
        return False

    url = f"{ORG_ENDPOINT_URL}/{org_id}"
    json = {
        "custom_role_mapping_name": custom_role_mapping_name,
    }

    response = requests.put(
        url,
        json=json,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise UpdateUserMetadataException(response.json())
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError(
            "Unknown error when subscribing an org to a custom role mapping"
        )

    return True


####################
#      DELETE      #
####################


def _delete_org(auth_hostname, integration_api_key, org_id) -> bool:
    if not _is_valid_id(org_id):
        return False

    url = f"{ORG_ENDPOINT_URL}/{org_id}"

    response = requests.delete(
        url,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when deleting org")

    return True

def _revoke_pending_org_invite(auth_hostname, integration_api_key, org_id, invitee_email) -> bool:

    url = BASE_ENDPOINT_URL + "/pending_org_invites"
    json = {"org_id": org_id, "invitee_email": invitee_email}

    response = requests.delete(
        url,
        json=json,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif not response.ok:
        raise RuntimeError("Unknown error when revoking pending org invite")

    return response.json()


def _delete_saml_connection(auth_hostname, integration_api_key, org_id) -> bool:
    if not _is_valid_id(org_id):
        return False

    url = f"{BASE_ENDPOINT_URL}/saml_idp_metadata/{org_id}"

    response = requests.delete(
        url,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif response.status_code == 404:
        return False
    elif not response.ok:
        raise RuntimeError("Unknown error when deleting SAML connection")

    return True


####################
#      HELPERS     #
####################


def _validate_org_api_key(auth_hostname, integration_api_key, api_key_token) -> OrgApiKeyValidation:
    api_key_validation = _validate_api_key(auth_hostname, integration_api_key, api_key_token)
    if not api_key_validation.org:
        raise EndUserApiKeyException({"api_key_token": ["Not an org API Key"]})
    return OrgApiKeyValidation(
        org=api_key_validation.org,
        metadata=api_key_validation.metadata,
        user=api_key_validation.user,
        user_in_org=api_key_validation.user_in_org,
    )
