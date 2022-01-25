import uuid
from dataclasses import dataclass


@dataclass
class Tool:
    id: uuid.UUID
    createdDate: str
    changedDate: str
    name: str
    tooltype: str
    scanPhase: str
    description: str
    title: str
    displayable: bool
    configurable: bool
    licenseType: str
    description: str
    uleska_approved: bool
    dockerImage: str
    customer_id: str
    command: str
    icon: str