from dataclasses import dataclass

@dataclass
class SpMetadata:
    entity_id: str
    acs_url: str
    logout_url: str

