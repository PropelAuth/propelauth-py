import requests

from propelauth_py.api import _ApiKeyAuth
from propelauth_py.errors import BadRequestException

ENDPOINT_PATH = "/api/backend/v1/magic_link"


####################
#       POST       #
####################
def _create_magic_link(
    auth_url,
    integration_api_key,
    email,
    redirect_to_url=None,
    expires_in_hours=None,
    create_new_user_if_one_doesnt_exist=None,
    user_signup_query_parameters=None,
):
    url = auth_url + ENDPOINT_PATH
    json = {"email": email}
    if redirect_to_url is not None:
        json["redirect_to_url"] = redirect_to_url
    if expires_in_hours is not None:
        json["expires_in_hours"] = expires_in_hours
    if user_signup_query_parameters is not None:
        json["user_signup_query_parameters"] = user_signup_query_parameters
    if create_new_user_if_one_doesnt_exist is not None:
        json[
            "create_new_user_if_one_doesnt_exist"
        ] = create_new_user_if_one_doesnt_exist

    response = requests.post(url, json=json, auth=_ApiKeyAuth(integration_api_key))
    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif not response.ok:
        raise RuntimeError("Unknown error when creating magic link")

    return response.json()
