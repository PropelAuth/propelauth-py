from typing import Any, Dict, Optional
from propelauth_py.types.user import UserMetadata, Org
from propelauth_py.user import OrgMemberInfo

class ApiKeyFull:
    def __init__(
        self,
        api_key_id: str,
        created_at: int,
        expires_at_seconds: Optional[int],
        metadata: Optional[Dict[str, Any]],
        user_id: Optional[str],
        org_id: Optional[str]
    ):
        self.api_key_id = api_key_id
        self.created_at = created_at
        self.expires_at_seconds = expires_at_seconds
        self.metadata = metadata
        self.user_id = user_id
        self.org_id = org_id

    def __repr__(self): 
        return (
            f"ApiKeyFull(api_key_id={self.api_key_id}, created_at={self.created_at}, "
            f"expires_at_seconds={self.expires_at_seconds}, metadata={self.metadata}, "
            f"user_id={self.user_id}, org_id={self.org_id})"
        )
    def __eq__(self, other):
        return isinstance(other, ApiKeyFull)
    
class ApiKeyResultPage:
    def __init__(
        self,
        api_keys: list[ApiKeyFull],
        total_api_keys: int,
        current_page: int,
        page_size: int,
        has_more_results: bool
    ):
        self.api_keys = api_keys
        self.total_api_keys = total_api_keys
        self.current_page = current_page
        self.page_size = page_size
        self.has_more_results = has_more_results
        
    def __repr__(self): 
        return (
            f"ApiKeyResultPage(api_keys={self.api_keys}, total_api_keys={self.total_api_keys}, "
            f"current_page={self.current_page}, page_size={self.page_size}, "
            f"has_more_results={self.has_more_results})"
        )
    def __eq__(self, other):
        return isinstance(other, ApiKeyResultPage)
    
    
class ApiKeyNew:
    def __init__(
        self,
        api_key_id: str,
        api_key_token: str,
    ):
        self.api_key_id = api_key_id
        self.api_key_token = api_key_token
        
    def __repr__(self): 
        return (
            f"ApiKeyNew(api_key_id={self.api_key_id}, api_key_token={self.api_key_token})"
        )
    def __eq__(self, other):
        return isinstance(other, ApiKeyNew)
    
class ApiKeyValidation:
    def __init__(
        self,
        metadata: Optional[Dict[str, Any]],
        user: Optional[UserMetadata],
        org: Optional[Org],
        user_in_org: Optional[OrgMemberInfo]
    ):
        self.metadata = metadata
        self.user = user
        self.org = org
        self.user_in_org = user_in_org
        
    def __repr__(self): 
        return (
            f"ApiKeyNew(metadata={self.metadata}, user={self.user}, org={self.org}, user_in_org={self.user_in_org})"
        )
    def __eq__(self, other):
        return isinstance(other, ApiKeyValidation)
