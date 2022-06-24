from collections import namedtuple
from typing import List, Dict, Set

RoleMetadata = namedtuple("RoleMetadata", [
    "name", "permissions", "parent"
])


def create_role_helper(role_metadata_list: List[RoleMetadata]):
    role_to_permissions = {}
    role_to_parent = {}
    for role_metadata in role_metadata_list:
        role_to_permissions[role_metadata.name] = set(role_metadata.permissions)
        role_to_parent[role_metadata.name] = role_metadata.parent

    return RoleHelper(role_to_permissions, role_to_parent)


class RoleHelper:
    def __init__(self, role_to_permissions: Dict[str, Set[str]], role_to_parent: Dict[str, str]):
        self.role_to_permissions = role_to_permissions
        self.role_to_parent = role_to_parent
        self.num_permissions = len(role_to_permissions)

    def is_valid_role(self, user_role: str):
        return user_role in self.role_to_permissions

    # assumption is that the roles are checked and valid already
    def is_parent_or_equal_to(self, target_role: str, starting_role: str):
        if target_role == starting_role:
            return True

        # Search up the tree starting at the source
        current_role = starting_role

        # Be extra safe here to avoid infinite loops and only loop for as many roles exist
        for _ in range(self.num_permissions):
            current_role = self.role_to_parent.get(current_role)

            if current_role is None:
                # If there is no parent, we've reached the top and not found the destination
                return False
            elif current_role == target_role:
                return True

        return False

    # assumption is that the roles are checked and valid already
    def role_includes_all_permissions(self, user_role: str, required_permissions: List[str]):
        permissions = self.role_to_permissions.get(user_role)
        for required_permission in required_permissions:
            if required_permission not in permissions:
                return False
        return True
