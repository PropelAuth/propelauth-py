from uuid import uuid4

from propelauth_py.types.login_method import (
    PasswordLoginMethod,
    SamlLoginProvider,
    SamlSsoLoginMethod,
    SocialLoginProvider,
    SocialSsoLoginMethod,
    UnknownLoginMethod,
)
from propelauth_py.user import _to_user, User, OrgMemberInfo


def test_to_user_without_orgs():
    user_id = str(uuid4())
    email = str(uuid4())
    login_method = {
        "login_method": "password",
    }
    user = _to_user({"user_id": user_id, "email": email, "login_method": login_method})
    expected_user = User(user_id, None, email, login_method=PasswordLoginMethod())
    assert user == expected_user


def test_to_user_with_no_login_method():
    user_id = str(uuid4())
    email = str(uuid4())
    user = _to_user({"user_id": user_id, "email": email})
    expected_user = User(user_id, None, email, login_method=UnknownLoginMethod())
    assert user == expected_user


def test_to_user():
    user_id = str(uuid4())
    email = str(uuid4())
    first_name = str(uuid4())
    last_name = str(uuid4())
    username = str(uuid4())
    org_role_structure = "single_role_in_hierarchy"
    org_a = {
        "org_id": str(uuid4()),
        "org_name": "orgA",
        "org_metadata": {"org_metadata_key_a": "org_metadata_value_a"},
        "user_role": "Owner",
        "inherited_user_roles_plus_current_role": ["Owner", "Admin", "Member"],
        "user_permissions": ["View", "Edit", "Delete"],
        "org_role_structure": org_role_structure,
        "url_safe_org_name": "orga",
        "additional_roles": [],
    }
    org_b = {
        "org_id": str(uuid4()),
        "org_name": "orgB",
        "org_metadata": {"org_metadata_key_b": "org_metadata_value_b"},
        "user_role": "Admin",
        "inherited_user_roles_plus_current_role": ["Admin", "Member"],
        "user_permissions": ["View", "Edit"],
        "org_role_structure": org_role_structure,
        "url_safe_org_name": "orgb",
        "additional_roles": [],
    }
    org_c = {
        "org_id": str(uuid4()),
        "org_name": "orgC",
        "org_metadata": {"org_metadata_key_c": "org_metadata_value_c"},
        "user_role": "Member",
        "inherited_user_roles_plus_current_role": ["Member"],
        "user_permissions": ["View"],
        "org_role_structure": org_role_structure,
        "url_safe_org_name": "orgc",
        "additional_roles": [],
    }
    org_id_to_org_member_info = {
        org_a["org_id"]: org_a,
        org_b["org_id"]: org_b,
        org_c["org_id"]: org_c,
    }
    login_method = {
        "login_method": "saml_sso",
        "provider": "Okta",
        "org_id": org_a["org_id"],
    }

    user = _to_user(
        {
            "user_id": user_id,
            "org_id_to_org_member_info": org_id_to_org_member_info,
            "email": email,
            "first_name": first_name,
            "last_name": last_name,
            "username": username,
            "login_method": login_method,
        }
    )

    expected_org_id_to_org_member_info = {
        org_a["org_id"]: OrgMemberInfo(
            org_id=org_a["org_id"],
            org_name=org_a["org_name"],
            org_metadata=org_a["org_metadata"],
            user_assigned_role="Owner",
            user_inherited_roles_plus_current_role=["Owner", "Admin", "Member"],
            user_permissions=["View", "Edit", "Delete"],
            org_role_structure=org_role_structure,
            url_safe_org_name=org_a["url_safe_org_name"],
            assigned_additional_roles=[],
        ),
        org_b["org_id"]: OrgMemberInfo(
            org_id=org_b["org_id"],
            org_name=org_b["org_name"],
            org_metadata=org_b["org_metadata"],
            user_assigned_role="Admin",
            user_inherited_roles_plus_current_role=["Admin", "Member"],
            user_permissions=["View", "Edit"],
            org_role_structure=org_role_structure,
            url_safe_org_name=org_b["url_safe_org_name"],
            assigned_additional_roles=[],
        ),
        org_c["org_id"]: OrgMemberInfo(
            org_id=org_c["org_id"],
            org_name=org_c["org_name"],
            org_metadata=org_c["org_metadata"],
            user_assigned_role="Member",
            user_inherited_roles_plus_current_role=["Member"],
            user_permissions=["View"],
            org_role_structure=org_role_structure,
            url_safe_org_name=org_c["url_safe_org_name"],
            assigned_additional_roles=[],
        ),
    }
    expected_user = User(
        user_id=user_id,
        org_id_to_org_member_info=expected_org_id_to_org_member_info,
        email=email,
        first_name=first_name,
        last_name=last_name,
        username=username,
        login_method=SamlSsoLoginMethod(
            provider=SamlLoginProvider.OKTA, org_id=org_a["org_id"]
        ),
    )

    assert user == expected_user


def test_to_user_with_active_org():
    user_id = str(uuid4())
    email = str(uuid4())
    first_name = str(uuid4())
    last_name = str(uuid4())
    username = str(uuid4())
    org_role_structure = "single_role_in_hierarchy"
    org_member_info = {
        "org_id": str(uuid4()),
        "org_name": "orgA",
        "org_metadata": {"org_metadata_key_a": "org_metadata_value_a"},
        "user_role": "Owner",
        "inherited_user_roles_plus_current_role": ["Owner", "Admin", "Member"],
        "user_permissions": ["View", "Edit", "Delete"],
        "org_role_structure": org_role_structure,
        "url_safe_org_name": "orga",
        "additional_roles": [],
    }
    login_method = {
        "login_method": "social_sso",
        "provider": "Google",
        "org_id": None,
    }

    user = _to_user(
        {
            "user_id": user_id,
            "org_member_info": org_member_info,
            "email": email,
            "first_name": first_name,
            "last_name": last_name,
            "username": username,
            "login_method": login_method,
        }
    )

    expected_org_id_to_org_member_info = {
        org_member_info["org_id"]: OrgMemberInfo(
            org_id=org_member_info["org_id"],
            org_name=org_member_info["org_name"],
            org_metadata=org_member_info["org_metadata"],
            user_assigned_role="Owner",
            user_inherited_roles_plus_current_role=["Owner", "Admin", "Member"],
            user_permissions=["View", "Edit", "Delete"],
            org_role_structure=org_role_structure,
            url_safe_org_name=org_member_info["url_safe_org_name"],
            assigned_additional_roles=[],
        ),
    }
    expected_user = User(
        user_id=user_id,
        org_id_to_org_member_info=expected_org_id_to_org_member_info,
        email=email,
        first_name=first_name,
        last_name=last_name,
        username=username,
        active_org_id=org_member_info["org_id"],
        login_method=SocialSsoLoginMethod(provider=SocialLoginProvider.GOOGLE),
    )

    assert user == expected_user

def test_to_user_multi_role():
    user_id = str(uuid4())
    email = str(uuid4())
    first_name = str(uuid4())
    last_name = str(uuid4())
    username = str(uuid4())
    org_role_structure = "multi_role"
    org_a = {
        "org_id": str(uuid4()),
        "org_name": "orgA",
        "org_metadata": {"org_metadata_key_a": "org_metadata_value_a"},
        "user_role": "Owner",
        "inherited_user_roles_plus_current_role": ["Owner"],
        "user_permissions": ["View", "Edit", "Delete"],
        "org_role_structure": org_role_structure,
        "url_safe_org_name": "orga",
        "additional_roles": ["Billing", "Finance"],
    }
    org_b = {
        "org_id": str(uuid4()),
        "org_name": "orgB",
        "org_metadata": {"org_metadata_key_b": "org_metadata_value_b"},
        "user_role": "Member",
        "inherited_user_roles_plus_current_role": ["Member"],
        "user_permissions": ["View", "Edit"],
        "org_role_structure": org_role_structure,
        "url_safe_org_name": "orgb",
        "additional_roles": ["IT"],
    }
    org_c = {
        "org_id": str(uuid4()),
        "org_name": "orgC",
        "org_metadata": {"org_metadata_key_c": "org_metadata_value_c"},
        "user_role": "Contractor",
        "inherited_user_roles_plus_current_role": ["Contractor"],
        "user_permissions": ["View"],
        "org_role_structure": org_role_structure,
        "url_safe_org_name": "orgc",
        "additional_roles": [],
    }
    org_id_to_org_member_info = {
        org_a["org_id"]: org_a,
        org_b["org_id"]: org_b,
        org_c["org_id"]: org_c,
    }

    user = _to_user(
        {
            "user_id": user_id,
            "org_id_to_org_member_info": org_id_to_org_member_info,
            "email": email,
            "first_name": first_name,
            "last_name": last_name,
            "username": username,
        }
    )

    expected_org_id_to_org_member_info = {
        org_a["org_id"]: OrgMemberInfo(
            org_id=org_a["org_id"],
            org_name=org_a["org_name"],
            org_metadata=org_a["org_metadata"],
            user_assigned_role="Owner",
            user_inherited_roles_plus_current_role=["Owner"],
            user_permissions=["View", "Edit", "Delete"],
            org_role_structure=org_role_structure,
            url_safe_org_name=org_a["url_safe_org_name"],
            assigned_additional_roles=["Billing", "Finance"],
        ),
        org_b["org_id"]: OrgMemberInfo(
            org_id=org_b["org_id"],
            org_name=org_b["org_name"],
            org_metadata=org_b["org_metadata"],
            user_assigned_role="Member",
            user_inherited_roles_plus_current_role=["Member"],
            user_permissions=["View", "Edit"],
            org_role_structure=org_role_structure,
            url_safe_org_name=org_b["url_safe_org_name"],
            assigned_additional_roles=["IT"],
        ),
        org_c["org_id"]: OrgMemberInfo(
            org_id=org_c["org_id"],
            org_name=org_c["org_name"],
            org_metadata=org_c["org_metadata"],
            user_assigned_role="Contractor",
            user_inherited_roles_plus_current_role=["Contractor"],
            user_permissions=["View"],
            org_role_structure=org_role_structure,
            url_safe_org_name=org_c["url_safe_org_name"],
            assigned_additional_roles=[],
        ),
    }
    expected_user = User(
        user_id=user_id,
        org_id_to_org_member_info=expected_org_id_to_org_member_info,
        email=email,
        first_name=first_name,
        last_name=last_name,
        username=username,
        login_method=UnknownLoginMethod(),
    )

    assert user == expected_user