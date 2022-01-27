import requests

from api import uleska_api


def scan_with_toolkit(host: str, token: str, application_id: str, version_id: str, toolkit_id: str) -> requests.Response:
    api = uleska_api.get_api(host, token)
    url = 'SecureDesigner/api/v1/applications/{}/versions/{}/scan/{}'.format(application_id, version_id, toolkit_id)
    return api.get(url)


def get_scans(host: str, token: str) -> requests.Response:
    api = uleska_api.get_api(host, token)
    url = 'SecureDesigner/api/v1/scans'
    return api.get(url)