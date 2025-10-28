from typing import Optional
import requests
import httpx
from propelauth_py.api import _ApiKeyAuth, _is_valid_id, _auth_hostname_header, BACKEND_API_BASE_URL, _get_async_headers
from propelauth_py.errors import RateLimitedException
from dataclasses import dataclass

ENDPOINT_URL = f"{BACKEND_API_BASE_URL}/api/backend/v1/employee"

    
@dataclass
class FetchEmployeeResponse:
    email: str

    def __getitem__(self, key):
        return getattr(self, key)

def _fetch_employee_by_id(auth_hostname, integration_api_key, employee_id) -> Optional[FetchEmployeeResponse]:
    if not _is_valid_id(employee_id):
        return None

    url = f"{ENDPOINT_URL}/{employee_id}"

    response = requests.get(
        url,
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 404:
        return None
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching employee")

    json_response = response.json()
    return FetchEmployeeResponse(
        email=json_response.get('email'),
    )
    
async def _fetch_employee_by_id_async(
    httpx_client: httpx.AsyncClient,
    auth_hostname,
    integration_api_key,
    employee_id
) -> Optional[FetchEmployeeResponse]:
    if not _is_valid_id(employee_id):
        return None

    url = f"{ENDPOINT_URL}/{employee_id}"

    response = await httpx_client.get(
        url=url,
        headers=_get_async_headers(auth_hostname=auth_hostname, integration_api_key=integration_api_key)
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 404:
        return None
    response.raise_for_status()
    json_response = response.json()
    return FetchEmployeeResponse(
       email=json_response.get('email'),
    )