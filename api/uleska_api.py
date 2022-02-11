import requests

from typing import Optional

from requests.adapters import HTTPAdapter
from urllib3 import Retry

__instance = None
retry_strategy = Retry(
    total=3,
    status_forcelist=[504],
    method_whitelist=["GET"]
)


def get_api(host, token):
    return UleskaApi(host, token)


class UleskaApi:
    def __new__(cls, host: Optional[str] = None, api_token: Optional[str] = None):
        if not hasattr(cls, 'instance'):
            cls.instance = super(UleskaApi, cls).__new__(cls)
        return cls.instance

    def __init__(self, host: Optional[str] = None, api_token: Optional[str] = None):
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session = requests.Session()
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        if api_token is not None:
            self.session.headers.update(
                {
                    "Authorization": "Bearer " + api_token
                }
            )
        self.host = host
        global __instance
        __instance = self

    def get(self, path: str) -> requests.Response:
        response = self.session.get(self.host + path)
        response.raise_for_status()
        return response

    def post(self, path: str, data: dict) -> requests.Response:
        response = self.session.post(self.host + path, json=data)
        response.raise_for_status()
        return response
