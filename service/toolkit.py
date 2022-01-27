from api.toolkit_api import get_toolkits
from model.toolkit import Toolkit
from model.toolkit_and_tools import ToolkitAndTools


def get_toolkit_id_from_name(host: str, token: str, toolkit_name: str, print_json: bool) -> str:
    toolkit_id: str = None
    toolkits_and_tools: [ToolkitAndTools] = get_toolkits(host, token)
    for toolkit_and_tools in toolkits_and_tools:
        toolkit: Toolkit = toolkit_and_tools.toolkit
        if toolkit["name"] == toolkit_name:
            toolkit_id = toolkit["id"]
            if not print_json:
                print("Toolkit Id found for [" + toolkit_name + "]: " + str(toolkit_id))
    if toolkit_id is None:
        raise ValueError("No Toolkit Id for Toolkit named: " + toolkit_name)
    return toolkit_id
