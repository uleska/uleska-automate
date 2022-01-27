import requests

from typing import Optional

__instance = None


def get_api(host, token):
    return UleskaApi(host, token)


class UleskaApi:

    def __new__(cls, host: Optional[str] = None, api_token: Optional[str] = None):
        if not hasattr(cls, 'instance'):
            cls.instance = super(UleskaApi, cls).__new__(cls)
        return cls.instance

    def __init__(self, host: Optional[str] = None, api_token: Optional[str] = None):
        self.session = requests.Session()
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
        response = self.session.get(self.host + path, verify=False)
        response.raise_for_status()
        return response

    def post(self, path: str, data: dict) -> requests.Response:
        response = self.session.post(self.host + path, json=data)
        response.raise_for_status()
        return response
