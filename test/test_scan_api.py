from unittest import TestCase
from mockito import when, mock
import requests
from uuid import UUID

from api import uleska_api
from api.scan_api import scan_with_toolkit


class ScanApiTest(TestCase):

    def test_scan_with_toolkit(self):
        # given
        application_id = '30126349-fc96-416c-bae3-76f613e13ee6'
        version_id = '60da176d-6fa7-4490-a607-7c1387cdc4dd'
        toolkit_id = '4ae4f51f-5b8c-490a-bda1-4d48f3aa650c'
        api = mock(spec=uleska_api.UleskaApi)
        response = mock(spec=requests.Response)
        when(uleska_api).get_api(any, any).thenReturn(api)
        when(api).get(
            'SecureDesigner/api/v1/applications/30126349-fc96-416c-bae3-76f613e13ee6/versions/60da176d-6fa7-4490-a607-7c1387cdc4dd/scan/4ae4f51f-5b8c-490a-bda1-4d48f3aa650c').thenReturn(
            response)

        # when
        result = scan_with_toolkit('host', 'token', application_id, version_id, toolkit_id)

        # then
        self.assertEqual(response, result)
