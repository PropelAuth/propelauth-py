from uuid import uuid4

from propelauth_py.user import _to_user, User, OrgMemberInfo


def test_to_user_without_orgs():
    user_id = str(uuid4())
    user = _to_user({"user_id": user_id})
    expected_user = User(user_id, None)
    assert user == expected_user


def test_to_user():
    user_id = str(uuid4())
    org_a = {
        "org_id": str(uuid4()),
        "org_name": "orgA",
        "user_role": "Owner",
        "inherited_user_roles_plus_current_role": ["Owner", "Admin", "Member"],
        "user_permissions": ["View", "Edit", "Delete"],
    }
    org_b = {
        "org_id": str(uuid4()),
        "org_name": "orgB",
        "user_role": "Admin",
        "inherited_user_roles_plus_current_role": ["Admin", "Member"],
        "user_permissions": ["View", "Edit"],
    }
    org_c = {
        "org_id": str(uuid4()),
        "org_name": "orgC",
        "user_role": "Member",
        "inherited_user_roles_plus_current_role": ["Member"],
        "user_permissions": ["View"],
    }
    org_id_to_org_member_info = {
        org_a["org_id"]: org_a,
        org_b["org_id"]: org_b,
        org_c["org_id"]: org_c,
    }

    user = _to_user({"user_id": user_id, "org_id_to_org_member_info": org_id_to_org_member_info})

    expected_org_id_to_org_member_info = {
        org_a["org_id"]: OrgMemberInfo(
            org_id=org_a["org_id"],
            org_name=org_a["org_name"],
            user_assigned_role="Owner",
            user_inherited_roles_plus_current_role=["Owner", "Admin", "Member"],
            user_permissions=["View", "Edit", "Delete"],
        ),
        org_b["org_id"]: OrgMemberInfo(
            org_id=org_b["org_id"],
            org_name=org_b["org_name"],
            user_assigned_role="Admin",
            user_inherited_roles_plus_current_role=["Admin", "Member"],
            user_permissions=["View", "Edit"],
        ),
        org_c["org_id"]: OrgMemberInfo(
            org_id=org_c["org_id"],
            org_name=org_c["org_name"],
            user_assigned_role="Member",
            user_inherited_roles_plus_current_role=["Member"],
            user_permissions=["View"],
        )
    }
    expected_user = User(user_id, expected_org_id_to_org_member_info)

    assert user == expected_user
