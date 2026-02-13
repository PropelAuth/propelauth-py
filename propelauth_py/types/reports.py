from dataclasses import dataclass
from typing import Optional, List
from enum import Enum

# org report types

@dataclass
class OrgReportRecord:
    id: str
    report_id: str
    org_id: str
    name: str
    num_users: int
    org_created_at: int
    extra_properties: dict

@dataclass
class OrgReport:
    org_reports: List[OrgReportRecord]
    current_page: int
    total_count: int
    page_size: int
    has_more_results: bool
    report_time: int

class OrgReportType(Enum):
    ATTRITION = "attrition"
    REENGAGEMENT = "reengagement"
    GROWTH = "growth"
    CHURN = "churn"

# user report types

@dataclass
class UserOrgMembershipForReport:
    display_name: str
    org_id: str
    user_role: str

@dataclass
class UserReportRecord:
    id: str
    report_id: str
    user_id: str
    email: str
    user_created_at: int
    last_active_at: int
    username: Optional[str]
    first_name: Optional[str]
    last_name: Optional[str]
    org_data: Optional[List[UserOrgMembershipForReport]]
    extra_properties: dict

@dataclass
class UserReport:
    user_reports: List[UserReportRecord]
    current_page: int
    total_count: int
    page_size: int
    has_more_results: bool
    report_time: int

class UserReportType(Enum):
    REENGAGEMENT = "reengagement"
    CHURN = "churn"
    TOP_INVITERS = "top_inviter"
    CHAMPION = "champion"

# report interval options

class ReengagementReportInterval(Enum):
    WEEKLY = "Weekly"
    MONTHLY = "Monthly"

class ChurnReportInterval(Enum):
    SEVEN_DAYS = "7"
    FOURTEEN_DAYS = "14"
    THIRTY_DAYS = "30"

class GrowthReportInterval(Enum):
    THIRTY_DAYS = "30"
    SIXTY_DAYS = "60"
    NINETY_DAYS = "90"

class TopInviterReportInterval(Enum):
    THIRTY_DAYS = "30"
    SIXTY_DAYS = "60"
    NINETY_DAYS = "90"

class ChampionReportInterval(Enum):
    THIRTY_DAYS = "30"
    SIXTY_DAYS = "60"
    NINETY_DAYS = "90"

class AttritionReportInterval(Enum):
    THIRTY_DAYS = "30"
    SIXTY_DAYS = "60"
    NINETY_DAYS = "90"

