from api import uleska_api
from model.toolkit import Toolkit
from model.toolkit_and_tools import ToolkitAndTools


def get_toolkits(host: str, token: str) -> [ToolkitAndTools]:
    api = uleska_api.get_api(host, token)
    url = 'SecureDesigner/api/v1/toolkits'
    response = api.get(url)
    toolkits_and_tools = []
    for toolkit_and_tool in response.json():
        toolkit = Toolkit(**toolkit_and_tool["toolkit"])
        toolkits_and_tools.append(ToolkitAndTools(toolkit, toolkit_and_tool["tools"]))
    return toolkits_and_tools

