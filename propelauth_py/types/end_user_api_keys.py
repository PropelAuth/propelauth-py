from typing import Any, Dict, Optional, List
from propelauth_py.types.user import UserMetadata, OrgFromApiKey
from propelauth_py.user import OrgMemberInfo
from dataclasses import dataclass

@dataclass
class ApiKeyFull:
    api_key_id: str
    created_at: int
    expires_at_seconds: Optional[int]
    metadata: Optional[Dict[str, Any]]
    user_id: Optional[str]
    org_id: Optional[str]
    
    def __getitem__(self, key):
        return getattr(self, key)

@dataclass
class ApiKeyResultPage:
    api_keys: List[ApiKeyFull]
    total_api_keys: int
    current_page: int
    page_size: int
    has_more_results: bool

    def __getitem__(self, key):
        return getattr(self, key)

@dataclass
class ApiKeyNew:
    api_key_id: str
    api_key_token: str

    def __getitem__(self, key):
        return getattr(self, key)

@dataclass
class ApiKeyValidation:
    metadata: Optional[Dict[str, Any]]
    user: Optional[UserMetadata]
    org: Optional[OrgFromApiKey]
    user_in_org: Optional[OrgMemberInfo]

    def __getitem__(self, key):
        return getattr(self, key)
