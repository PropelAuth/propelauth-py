from dataclasses import dataclass
from typing import Literal, Union

@dataclass
class SpMetadata:
    entity_id: str
    acs_url: str
    logout_url: str

class SamlIdpMetadata(dict):
    def __init__(self, idp_entity_id: str, idp_sso_url: str, idp_certificate: str, provider: str):
        super().__init__()
        self["idp_entity_id"] = idp_entity_id
        self["idp_sso_url"] = idp_sso_url
        self["idp_certificate"] = idp_certificate
        self["provider"] = provider

    @property
    def idp_entity_id(self):
        return self["idp_entity_id"]

    @property
    def idp_sso_url(self):
        return self["idp_sso_url"]

    @property
    def idp_certificate(self):
        return self["idp_certificate"]

    @property
    def provider(self):
        return self["provider"]


@dataclass
class SetOidcIdpMetadataRequestBase:
    org_id: str
    client_id: str
    client_secret: str
    uses_pkce: bool
    
    def __getitem__(self, key):
        return getattr(self, key)


@dataclass
class SetGenericOidcMetadataRequest(SetOidcIdpMetadataRequestBase):
    idp_type: Literal["Generic"]
    auth_url: str
    token_url: str
    userinfo_url: str
    
    def __getitem__(self, key):
        return getattr(self, key)


@dataclass
class SetOktaOidcMetadataRequest(SetOidcIdpMetadataRequestBase):
    idp_type: Literal["Okta"]
    okta_sso_domain: str
    
    def __getitem__(self, key):
        return getattr(self, key)


@dataclass
class SetAzureOidcMetadataRequest(SetOidcIdpMetadataRequestBase):
    idp_type: Literal["Azure"]
    entra_tenant_id: str
    
    def __getitem__(self, key):
        return getattr(self, key)

SetOidcIdpMetadataRequest = Union[
    SetGenericOidcMetadataRequest,
    SetOktaOidcMetadataRequest,
    SetAzureOidcMetadataRequest,
]
