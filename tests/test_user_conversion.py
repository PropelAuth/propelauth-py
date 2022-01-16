from uuid import uuid4

from propelauth_py.user import _to_user, User, OrgMemberInfo, UserRole


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
    }
    org_b = {
        "org_id": str(uuid4()),
        "org_name": "orgB",
        "user_role": "Admin",
    }
    org_c = {
        "org_id": str(uuid4()),
        "org_name": "orgC",
        "user_role": "Member",
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
            user_role=UserRole.Owner,
        ),
        org_b["org_id"]: OrgMemberInfo(
            org_id=org_b["org_id"],
            org_name=org_b["org_name"],
            user_role=UserRole.Admin,
        ),
        org_c["org_id"]: OrgMemberInfo(
            org_id=org_c["org_id"],
            org_name=org_c["org_name"],
            user_role=UserRole.Member,
        )
    }
    expected_user = User(user_id, expected_org_id_to_org_member_info)

    assert user == expected_user
