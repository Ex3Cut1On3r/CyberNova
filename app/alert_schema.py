from pydantic import BaseModel, Field
from typing import Dict, Optional

class Alert(BaseModel):
    id: str
    source: str                   # SIM | DONKI
    type: str                     # e.g., GPS Spoofing, High Temp
    severity: str                 # INFO | LOW | MEDIUM | HIGH | CRITICAL
    timestamp: str                # ISO 8601
    entity_id: Optional[str] = None
    labels: Dict[str, str] = {}
    description: str
    fingerprint: str = Field(..., description="dedupe hash")
