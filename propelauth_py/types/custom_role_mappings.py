from dataclasses import dataclass
from typing import List

@dataclass
class CustomRoleMapping:
    custom_role_mapping_name: str
    num_orgs_subscribed: int

@dataclass
class CustomRoleMappings:
    custom_role_mappings: List[CustomRoleMapping]