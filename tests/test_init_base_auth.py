import inspect
from propelauth_py import init_base_auth
from propelauth_py.api.user import (
    _fetch_user_metadata_by_user_id,
    _fetch_user_metadata_by_email,
    _fetch_user_metadata_by_username,
    _fetch_batch_user_metadata_by_user_ids,
    _fetch_batch_user_metadata_by_emails,
    _fetch_batch_user_metadata_by_usernames,
    _fetch_users_by_query,
    _fetch_users_in_org,
    _create_user,
    _update_user_email,
    _update_user_metadata,
    _delete_user,
    _disable_user,
    _enable_user,
    _update_user_password,
    _disable_user_2fa,
    _enable_user_can_create_orgs,
    _disable_user_can_create_orgs,
    _validate_personal_api_key,
)
from propelauth_py.api.org import (
    _fetch_org,
    _fetch_org_by_query,
    _create_org,
    _remove_user_from_org,
    _update_org_metadata,
    _add_user_to_org,
    _allow_org_to_setup_saml_connection,
    _disallow_org_to_setup_saml_connection,
    _validate_org_api_key,
)
from propelauth_py.api.magic_link import _create_magic_link
from propelauth_py.api.access_token import _create_access_token
from propelauth_py.api.migrate_user import _migrate_user_from_external_source
from propelauth_py.api.end_user_api_keys import (
    _fetch_api_key,
    _fetch_current_api_keys,
    _fetch_archived_api_keys,
    _create_api_key,
    _update_api_key,
    _delete_api_key,
    _validate_api_key,
)


def test_functions_imported():
    """
    Test that all API functions are imported in init_base_auth().
    """
    init_base_auth_nested_functions = [
        name.co_name
        for name in init_base_auth.__code__.co_consts
        if inspect.iscode(name)
    ]
    imported_functions = [
        _fetch_user_metadata_by_user_id,
        _fetch_user_metadata_by_email,
        _fetch_user_metadata_by_username,
        _fetch_batch_user_metadata_by_user_ids,
        _fetch_batch_user_metadata_by_emails,
        _fetch_batch_user_metadata_by_usernames,
        _fetch_users_by_query,
        _fetch_users_in_org,
        _create_user,
        _update_user_email,
        _update_user_metadata,
        _delete_user,
        _disable_user,
        _enable_user,
        _update_user_password,
        _disable_user_2fa,
        _enable_user_can_create_orgs,
        _disable_user_can_create_orgs,
        _validate_personal_api_key,
        _fetch_org,
        _fetch_org_by_query,
        _create_org,
        _remove_user_from_org,
        _update_org_metadata,
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
    ]

    missing_functions = []
    for func in imported_functions:
        function_name_with_underscore = func.__name__[1:]

        if function_name_with_underscore not in init_base_auth_nested_functions:
            missing_functions.append(function_name_with_underscore)

    assert len(missing_functions) == 0, f"Missing functions: {missing_functions}"
