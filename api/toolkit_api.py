from api import uleska_api
from model.toolkit import Toolkit
from model.toolkit_and_tools import ToolkitAndTools


def get_toolkits(host: str, token: str):
    api = uleska_api.get_api(host, token)
    url = '/SecureDesigner/api/v1/toolkits'
    response = api.get(url)
    toolkitAndTools = []
    for toolkitAndTool in response.json():
        toolkit = Toolkit(**toolkitAndTool["toolkit"])
        toolkitAndTools.append(ToolkitAndTools(toolkit, toolkitAndTool["tools"]))
    return toolkitAndTools

