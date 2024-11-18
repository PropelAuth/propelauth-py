import inspect

from propelauth_py import init_base_auth
from propelauth_py.api.access_token import _create_access_token
from propelauth_py.api.end_user_api_keys import (
    _create_api_key,
    _delete_api_key,
    _fetch_api_key,
    _fetch_archived_api_keys,
    _fetch_current_api_keys,
    _update_api_key,
    _validate_api_key,
)
from propelauth_py.api.magic_link import _create_magic_link
from propelauth_py.api.migrate_user import _migrate_user_from_external_source
from propelauth_py.api.org import (
    _add_user_to_org,
    _allow_org_to_setup_saml_connection,
    _change_user_role_in_org,
    _create_org,
    _create_org_saml_connection_link,
    _delete_org,
    _disallow_org_to_setup_saml_connection,
    _fetch_custom_role_mappings,
    _fetch_org,
    _fetch_org_by_query,
    _fetch_pending_invites,
    _remove_user_from_org,
    _revoke_pending_org_invite,
    _subscribe_org_to_role_mapping,
    _update_org_metadata,
    _validate_org_api_key,
    _fetch_saml_sp_metadata,
    _set_saml_idp_metadata,
    _saml_go_live,
    _delete_saml_connection,
)
from propelauth_py.api.user import (
    _clear_user_password,
    _create_user,
    _delete_user,
    _disable_user,
    _disable_user_2fa,
    _disable_user_can_create_orgs,
    _enable_user,
    _enable_user_can_create_orgs,
    _fetch_batch_user_metadata_by_emails,
    _fetch_batch_user_metadata_by_user_ids,
    _fetch_batch_user_metadata_by_usernames,
    _fetch_user_metadata_by_email,
    _fetch_user_metadata_by_user_id,
    _fetch_user_metadata_by_username,
    _fetch_user_signup_query_params_by_user_id,
    _fetch_users_by_query,
    _fetch_users_in_org,
    _invite_user_to_org,
    _logout_all_user_sessions,
    _resend_email_confirmation,
    _update_user_email,
    _update_user_metadata,
    _update_user_password,
    _validate_personal_api_key,
)
from tests.conftest import BASE_AUTH_URL, mock_api_and_init_auth, rsa_keys

IMPORTED_FUNCTIONS = [
    _fetch_user_metadata_by_user_id,
    _fetch_user_metadata_by_email,
    _fetch_user_metadata_by_username,
    _fetch_batch_user_metadata_by_user_ids,
    _fetch_batch_user_metadata_by_emails,
    _fetch_batch_user_metadata_by_usernames,
    _fetch_user_signup_query_params_by_user_id,
    _fetch_users_by_query,
    _fetch_users_in_org,
    _create_user,
    _update_user_email,
    _update_user_metadata,
    _delete_user,
    _disable_user,
    _enable_user,
    _update_user_password,
    _clear_user_password,
    _disable_user_2fa,
    _enable_user_can_create_orgs,
    _disable_user_can_create_orgs,
    _validate_personal_api_key,
    _fetch_org,
    _fetch_org_by_query,
    _fetch_pending_invites,
    _fetch_custom_role_mappings,
    _create_org,
    _remove_user_from_org,
    _update_org_metadata,
    _subscribe_org_to_role_mapping,
    _add_user_to_org,
    _allow_org_to_setup_saml_connection,
    _disallow_org_to_setup_saml_connection,
    _validate_org_api_key,
    _create_magic_link,
    _create_access_token,
    _migrate_user_from_external_source,
    _fetch_api_key,
    _fetch_current_api_keys,
    _fetch_archived_api_keys,
    _create_api_key,
    _update_api_key,
    _delete_api_key,
    _validate_api_key,
    _change_user_role_in_org,
    _delete_org,
    _invite_user_to_org,
    _resend_email_confirmation,
    _logout_all_user_sessions,
    _revoke_pending_org_invite,
    _create_org_saml_connection_link,
    _fetch_saml_sp_metadata,
    _set_saml_idp_metadata,
    _saml_go_live,
    _delete_saml_connection,
]


def test_all_functions_imported_in_init_base_auth():
    """
    Test that all API functions are imported in init_base_auth().
    """
    init_base_auth_nested_functions = [
        name.co_name
        for name in init_base_auth.__code__.co_consts
        if inspect.iscode(name)
    ]

    imported_functions_without_underscores = [
        func.__name__[1:] for func in IMPORTED_FUNCTIONS
    ]
    missing_functions = [
        func_name
        for func_name in init_base_auth_nested_functions
        if func_name not in imported_functions_without_underscores
    ]

    assert len(missing_functions) == 0, f"Missing functions: {missing_functions}"


def test_auth_tuple_contains_all_expected_functions(rsa_keys):
    """
    Test that the Auth tuple contains all expected functions.
    """
    mock_auth_class = mock_api_and_init_auth(
        BASE_AUTH_URL, 200, {"verifier_key_pem": rsa_keys.public_pem}
    )
    auth_methods = [
        func for func in dir(mock_auth_class)
        if callable(getattr(mock_auth_class, func)) and not func.startswith("_")
    ]
    imported_functions_without_underscores = [
        func.__name__[1:] for func in IMPORTED_FUNCTIONS
    ]
    missing_functions = [
        func_name
        for func_name in imported_functions_without_underscores
        if func_name not in auth_methods
    ]

    assert len(missing_functions) == 0, f"Missing functions: {missing_functions}"
