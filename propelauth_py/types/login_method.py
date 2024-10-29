from enum import Enum


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


class PasswordLoginMethod:
    def __init__(self):
        self.login_method = "password"
        self.provider = None
        self.org_id = None

    def __eq__(self, other):
        return isinstance(other, PasswordLoginMethod)


class MagicLinkLoginMethod:
    def __init__(self):
        self.login_method = "magic_link"
        self.provider = None
        self.org_id = None

    def __eq__(self, other):
        isinstance(other, MagicLinkLoginMethod)


class SocialSsoLoginMethod:
    def __init__(self, provider: SocialLoginProvider):
        self.login_method = "social_sso"
        self.provider = provider
        self.org_id = None

    def __eq__(self, other):
        if isinstance(other, SocialSsoLoginMethod):
            return (
                self.login_method == other.login_method
                and self.provider == other.provider
            )
        return False


class EmailConfirmationLinkLoginMethod:
    def __init__(self):
        self.login_method = "email_confirmation_link"
        self.provider = None
        self.org_id = None

    def __eq__(self, other):
        return isinstance(other, EmailConfirmationLinkLoginMethod)


class SamlSsoLoginMethod:
    def __init__(self, provider: SamlLoginProvider, org_id: str):
        self.login_method = "saml_sso"
        self.provider = provider
        self.org_id = org_id

    def __eq__(self, other):
        if isinstance(other, SamlSsoLoginMethod):
            return (
                self.login_method == other.login_method
                and self.provider == other.provider
                and self.org_id == other.org_id
            )
        return False


class ImpersonationLoginMethod:
    def __init__(self):
        self.login_method = "impersonation"
        self.provider = None
        self.org_id = None

    def __eq__(self, other):
        return isinstance(other, ImpersonationLoginMethod)


class GeneratedFromBackendApiLoginMethod:
    def __init__(self):
        self.login_method = "generated_from_backend_api"
        self.provider = None
        self.org_id = None

    def __eq__(self, other):
        return isinstance(other, GeneratedFromBackendApiLoginMethod)


class UnknownLoginMethod:
    def __init__(self):
        self.login_method = "unknown"
        self.provider = None
        self.org_id = None

    def __eq__(self, other):
        return isinstance(other, UnknownLoginMethod)


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
