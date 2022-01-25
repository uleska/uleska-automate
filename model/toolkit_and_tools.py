from dataclasses import dataclass
from model.toolkit import Toolkit


@dataclass
class ToolkitAndTools:
    toolkit: Toolkit
    tools: dict