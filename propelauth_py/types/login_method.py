from enum import Enum
from dataclasses import dataclass
from typing import Optional


class SocialLoginProvider(Enum):
    GOOGLE = "Google"
    GITHUB = "GitHub"
    MICROSOFT = "Microsoft"
    SLACK = "Slack"
    LINKEDIN = "LinkedIn"
    SALESFORCE = "Salesforce"
    XERO = "Xero"
    QUICKBOOKS_ONLINE = "QuickBooks Online"


class SamlLoginProvider(Enum):
    GOOGLE = "Google"
    RIPPLING = "Rippling"
    ONELOGIN = "OneLogin"
    JUMPCLOUD = "JumpCloud"
    OKTA = "Okta"
    AZURE = "Azure"
    DUO = "Duo"
    GENERIC = "Generic"


@dataclass
class PasswordLoginMethod:
    login_method: str = "password"
    provider = None
    org_id = None
    
    def __getitem__(self, key):
        return getattr(self, key)

@dataclass
class MagicLinkLoginMethod:
    login_method: str = "magic_link"
    provider = None
    org_id = None
    
    def __getitem__(self, key):
        return getattr(self, key)

@dataclass
class SocialSsoLoginMethod:
    provider: SocialLoginProvider
    login_method: str = "social_sso"
    org_id = None

    def __getitem__(self, key):
        return getattr(self, key)

@dataclass
class EmailConfirmationLinkLoginMethod:
    login_method: str = "email_confirmation_link"
    provider = None
    org_id = None
    
    def __getitem__(self, key):
        return getattr(self, key)

@dataclass
class SamlSsoLoginMethod:
    provider: SamlLoginProvider
    org_id: str
    login_method: str = "saml_sso"

    def __getitem__(self, key):
        return getattr(self, key)

@dataclass
class ImpersonationLoginMethod:
    login_method: str = "impersonation"
    provider = None
    org_id = None
    
    def __getitem__(self, key):
        return getattr(self, key)

@dataclass
class GeneratedFromBackendApiLoginMethod:
    login_method: str = "generated_from_backend_api"
    provider = None
    org_id = None
    
    def __getitem__(self, key):
        return getattr(self, key)

@dataclass
class UnknownLoginMethod:
    login_method: str = "unknown"
    provider = None
    org_id = None
    
    def __getitem__(self, key):
        return getattr(self, key)


def to_login_method(d={}):
    if "login_method" not in d:
        return UnknownLoginMethod()
    if d["login_method"] == "password":
        return PasswordLoginMethod()
    if d["login_method"] == "magic_link":
        return MagicLinkLoginMethod()
    if d["login_method"] == "social_sso":
        return SocialSsoLoginMethod(
            provider=SocialLoginProvider(d["provider"]),
        )
    if d["login_method"] == "email_confirmation_link":
        return EmailConfirmationLinkLoginMethod()
    if d["login_method"] == "saml_sso":
        return SamlSsoLoginMethod(
            provider=SamlLoginProvider(d["provider"]),
            org_id=d["org_id"],
        )
    if d["login_method"] == "impersonation":
        return ImpersonationLoginMethod()
    if d["login_method"] == "generated_from_backend_api":
        return GeneratedFromBackendApiLoginMethod()
    return UnknownLoginMethod()
