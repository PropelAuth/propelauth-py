from typing import Optional, List
from dataclasses import dataclass


@dataclass
class FetchOrgScimGroupsRequest:
    org_id: str
    user_id: Optional[str]
    page_size: Optional[int]
    page_number: Optional[int]
    
    def __getitem__(self, key):
        return getattr(self, key) 
        
        
@dataclass
class FetchScimGroupRequest:
    org_id: str
    group_id: str
    
    def __getitem__(self, key):
        return getattr(self, key)
        
@dataclass
class ScimGroupResult:
    group_id: str
    display_name: str
    externalIdFromIdp: Optional[str]
    
    def __getitem__(self, key):
        return getattr(self, key) 
        
@dataclass
class ScimGroupResultPage:
    groups: List[ScimGroupResult]
    page_number: int
    page_size: int
    total_groups: int
    
    def __getitem__(self, key):
        return getattr(self, key)
        
@dataclass
class ScimGroupMember:
    user_id: str
    
    def __getitem__(self, key):
        return getattr(self, key) 
        
@dataclass
class ScimGroup:
    group_id: str
    display_name: str
    externalIdFromIdp: Optional[str]
    members: List[ScimGroupMember]
    
    def __getitem__(self, key):
        return getattr(self, key)
