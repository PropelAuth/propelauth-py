from datetime import date
from typing import Optional
import requests
import httpx

from propelauth_py.types.user_insights import (
    ChartData,
    ChartMetric,
    ChartMetricCadence,
    ChartDataPoint,
    UserReportType,
    UserReportRecord,
    UserReport,
    OrgReportType,
    OrgReportRecord,
    OrgReport,
)

from propelauth_py.api import (
    _ApiKeyAuth,
    _format_params,
    BACKEND_API_BASE_URL,
    _auth_hostname_header,
)
from propelauth_py.errors import (
    BadRequestException,
    RateLimitedException,
)

BASE_ENDPOINT_URL = f"{BACKEND_API_BASE_URL}/api/backend/v1"

def _fetch_user_report(
        auth_hostname,
        integration_api_key,
        report_key: UserReportType,
        report_interval: Optional[str],
        page_size: Optional[int],
        page_number: Optional[int],
    ) -> UserReport:
    url = BASE_ENDPOINT_URL + "/user_report/" + report_key.value
    params = {
        "page_size": page_size,
        "page_number": page_number,
        "report_interval": report_interval,
    }
    response = requests.get(
        url,
        params=_format_params(params),
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching user reports")

    json_response = response.json()
    
    user_report_records = [
        UserReportRecord(
            id=report_record.get("id"),
            report_id=report_record.get("report_id"),
            user_id=report_record.get("user_id"),
            email=report_record.get("email"),
            username=report_record.get("username"),
            first_name=report_record.get("first_name"),
            last_name=report_record.get("last_name"),
            last_active_at=report_record.get("last_active_at"),
            user_created_at=report_record.get("user_created_at"),
            org_data=report_record.get("org_data"),
            extra_properties=report_record.get("extra_properties"),
        )
        for report_record in json_response.get("user_reports")
    ]
    
    return UserReport(
        user_reports=user_report_records,
        current_page=json_response.get("current_page"),
        page_size=json_response.get("page_size"),
        has_more_results=json_response.get("has_more_results"),
        total_count=json_response.get("total_count"),
        report_time=json_response.get("report_time"),
    )

async def _fetch_user_report_async(
    httpx_client: httpx.AsyncClient,
    auth_hostname,
    integration_api_key,
    report_key: UserReportType,
    report_interval: Optional[str],
    page_size: Optional[int],
    page_number: Optional[int],
) -> UserReport:
    url = BASE_ENDPOINT_URL + "/user_report/" + report_key.value
    params = {
        "page_size": page_size,
        "page_number": page_number,
        "report_interval": report_interval,
    }
    response = await httpx_client.get(
        url,
        params=_format_params(params),
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching user reports")

    response.raise_for_status()
    json_response = response.json()
    
    user_report_records = [
        UserReportRecord(
            id=report_record.get("id"),
            report_id=report_record.get("report_id"),
            user_id=report_record.get("user_id"),
            email=report_record.get("email"),
            username=report_record.get("username"),
            first_name=report_record.get("first_name"),
            last_name=report_record.get("last_name"),
            last_active_at=report_record.get("last_active_at"),
            user_created_at=report_record.get("user_created_at"),
            org_data=report_record.get("org_data"),
            extra_properties=report_record.get("extra_properties"),
        )
        for report_record in json_response.get("user_reports")
    ]
    
    return UserReport(
        user_reports=user_report_records,
        current_page=json_response.get("current_page"),
        page_size=json_response.get("page_size"),
        has_more_results=json_response.get("has_more_results"),
        total_count=json_response.get("total_count"),
        report_time=json_response.get("report_time"),
    )

def _fetch_org_report(
        auth_hostname,
        integration_api_key,
        report_key: OrgReportType,
        report_interval: str | None,
        page_size: int | None,
        page_number: int | None,
    ) -> OrgReport:
    url = BASE_ENDPOINT_URL + "/org_report/" + report_key.value
    params = {
        "page_size": page_size,
        "page_number": page_number,
        "report_interval": report_interval,
    }
    response = requests.get(
        url,
        params=_format_params(params),
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 426:
        raise RuntimeError(
            "Cannot use organizations unless B2B support is enabled. Enable it in your PropelAuth "
            "dashboard."
        )
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching org reports")

    json_response = response.json()
    
    org_report_records = [
        OrgReportRecord(
            id=report_record.get("id"),
            report_id=report_record.get("report_id"),
            org_id=report_record.get("org_id"),
            name=report_record.get("name"),
            num_users=report_record.get("num_users"),
            org_created_at=report_record.get("org_created_at"),
            extra_properties=report_record.get("extra_properties"),
        )
        for report_record in json_response.get("org_reports")
    ]
    
    return OrgReport(
        org_reports=org_report_records,
        current_page=json_response.get("current_page"),
        page_size=json_response.get("page_size"),
        has_more_results=json_response.get("has_more_results"),
        total_count=json_response.get("total_count"),
        report_time=json_response.get("report_time"),
    )

async def _fetch_org_report_async(
    httpx_client: httpx.AsyncClient,
    auth_hostname,
    integration_api_key,
    report_key: OrgReportType,
    report_interval: str | None,
    page_size: int | None,
    page_number: int | None,
) -> OrgReport:
    url = BASE_ENDPOINT_URL + "/org_report/" + report_key.value
    params = {
        "page_size": page_size,
        "page_number": page_number,
        "report_interval": report_interval,
    }
    response = await httpx_client.get(
        url,
        params=_format_params(params),
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 426:
        raise RuntimeError(
            "Cannot use organizations unless B2B support is enabled. Enable it in your PropelAuth "
            "dashboard."
        )
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching org reports")

    response.raise_for_status()
    json_response = response.json()
    
    org_report_records = [
        OrgReportRecord(
            id=report_record.get("id"),
            report_id=report_record.get("report_id"),
            org_id=report_record.get("org_id"),
            name=report_record.get("name"),
            num_users=report_record.get("num_users"),
            org_created_at=report_record.get("org_created_at"),
            extra_properties=report_record.get("extra_properties"),
        )
        for report_record in json_response.get("org_reports")
    ]
    
    return OrgReport(
        org_reports=org_report_records,
        current_page=json_response.get("current_page"),
        page_size=json_response.get("page_size"),
        has_more_results=json_response.get("has_more_results"),
        total_count=json_response.get("total_count"),
        report_time=json_response.get("report_time"),
    )

def _fetch_chart_metric_data(
    auth_hostname,
    integration_api_key,
    chart_metric: ChartMetric,
    cadence: ChartMetricCadence | None,
    start_date: date | None,
    end_date: date | None,
) -> ChartData:
    url = BASE_ENDPOINT_URL + "/chart_metrics/" + chart_metric.value
    params = {
        "cadence": cadence.value if cadence else None,
        "start_date": start_date.isoformat() if start_date else None,
        "end_date": end_date.isoformat() if end_date else None,
    }
    response = requests.get(
        url,
        params=_format_params(params),
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching chart metric data")

    json_response = response.json()
    metrics = [
        ChartDataPoint(
            date=data_point.get("date"),
            result=data_point.get("result"),
            cadence_completed=data_point.get("cadence_completed"),
        )
        for data_point in json_response.get("metrics", [])
    ]

    return ChartData(
        metrics=metrics,
        cadence=json_response.get("cadence"),
        chart_type=json_response.get("chart_type"),
    )

async def _fetch_chart_metric_data_async(
    httpx_client: httpx.AsyncClient,
    auth_hostname,
    integration_api_key,
    chart_metric: ChartMetric,
    cadence: ChartMetricCadence | None,
    start_date: date | None,
    end_date: date | None,
) -> ChartData:
    url = BASE_ENDPOINT_URL + "/chart_metrics/" + chart_metric.value
    params = {
        "cadence": cadence.value if cadence else None,
        "start_date": start_date.isoformat() if start_date else None,
        "end_date": end_date.isoformat() if end_date else None,
    }
    response = await httpx_client.get(
        url,
        params=_format_params(params),
        auth=_ApiKeyAuth(integration_api_key),
        headers=_auth_hostname_header(auth_hostname),
    )

    if response.status_code == 401:
        raise ValueError("integration_api_key is incorrect")
    elif response.status_code == 429:
        raise RateLimitedException(response.text)
    elif response.status_code == 400:
        raise BadRequestException(response.json())
    elif not response.ok:
        raise RuntimeError("Unknown error when fetching chart metric data")

    response.raise_for_status()
    json_response = response.json()
    metrics = [
        ChartDataPoint(
            date=data_point.get("date"),
            result=data_point.get("result"),
            cadence_completed=data_point.get("cadence_completed"),
        )
        for data_point in json_response.get("metrics", [])
    ]

    return ChartData(
        metrics=metrics,
        cadence=json_response.get("cadence"),
        chart_type=json_response.get("chart_type"),
    )