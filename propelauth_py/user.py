from propelauth_py.errors import UnauthorizedException


class User:
    def __init__(self, user_id, org_id_to_org_member_info):
        self.user_id = user_id
        self.org_id_to_org_member_info = org_id_to_org_member_info

    def __eq__(self, other):
        if isinstance(other, User):
            return self.user_id == other.user_id and self.org_id_to_org_member_info == other.org_id_to_org_member_info
        return False


class OrgMemberInfo:
    def __init__(self, org_id, org_name, user_role_name):
        self.org_id = org_id
        self.org_name = org_name
        self.user_role_name = user_role_name

    def __eq__(self, other):
        if isinstance(other, OrgMemberInfo):
            return self.org_id == other.org_id and \
                   self.org_name == other.org_name and \
                   self.user_role_name == other.user_role_name
        return False


class UserAndOrgMemberInfo:
    def __init__(self, user, org_member_info):
        self.user = user
        self.org_member_info = org_member_info


def _to_org_member_info(org_id_to_org_member_info_json):
    if org_id_to_org_member_info_json is None:
        return None

    org_id_to_org_member_info = {}
    for org_id, org_member_info_json in org_id_to_org_member_info_json.items():
        org_id_to_org_member_info[org_id] = OrgMemberInfo(
            org_id=org_member_info_json["org_id"],
            org_name=org_member_info_json["org_name"],
            user_role_name=org_member_info_json["user_role"]
        )
    return org_id_to_org_member_info


def _to_user(decoded_token):
    user_id = decoded_token.get("user_id")
    if user_id is None:
        raise UnauthorizedException.invalid_payload_in_access_token()

    org_id_to_org_member_info = _to_org_member_info(decoded_token.get("org_id_to_org_member_info"))
    return User(user_id, org_id_to_org_member_info)