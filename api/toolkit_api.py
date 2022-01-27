import requests

from api import uleska_api
from api.uleska_api import UleskaApi
from model.toolkit import Toolkit
from model.toolkit_and_tools import ToolkitAndTools


def get_toolkits(host: str, token: str) -> [ToolkitAndTools]:
    api: UleskaApi = uleska_api.get_api(host, token)
    url: str = 'SecureDesigner/api/v1/toolkits'
    response: requests.Response = api.get(url)
    toolkits_and_tools: [ToolkitAndTools] = []
    for toolkit_and_tool in response.json():
        toolkit: Toolkit = Toolkit(**toolkit_and_tool["toolkit"])
        toolkits_and_tools.append(ToolkitAndTools(toolkit, toolkit_and_tool["tools"]))
    return toolkits_and_tools

