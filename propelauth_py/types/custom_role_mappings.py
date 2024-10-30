class CustomRoleMapping:
    def __init__(
        self,
        custom_role_mapping_name: str,
        num_orgs_subscribed: int
    ):
        self.custom_role_mapping_name = custom_role_mapping_name
        self.num_orgs_subscribed = num_orgs_subscribed

    def __repr__(self):
        return (
            f"CustomRoleMapping(custom_role_mapping_name={self.custom_role_mapping_name!r}, "
            f"num_orgs_subscribed={self.num_orgs_subscribed})"
        )
        
    def __eq__(self, other):
        return isinstance(other, CustomRoleMapping)

class CustomRoleMappings:
    def __init__(
        self,
        custom_role_mappings: list[CustomRoleMapping]
    ):
        self.custom_role_mappings = custom_role_mappings

    def __repr__(self):
        return (
            f"CustomRoleMappings(custom_role_mappings={self.custom_role_mappings!r})"
        )
        
    def __eq__(self, other):
        return isinstance(other, CustomRoleMappings)
