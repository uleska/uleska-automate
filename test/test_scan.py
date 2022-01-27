from unittest import TestCase

import requests
from mockito import mock, when, verify

from api import uleska_api
from service.scan import wait_for_scan_to_finish


class ScanTest(TestCase):

    def test_wait_for_scan_to_finish_with_no_running_scans(self):
        # given
        version_id = '111a01c8-a8c4-408b-b198-7bdfd07f25d3'
        api = mock(spec=uleska_api.UleskaApi)
        response = mock(spec=requests.Response)
        response.text = "[]"
        when(uleska_api).get_api(any, any).thenReturn(api)
        when(api).get('SecureDesigner/api/v1/scans').thenReturn(response)

        # when
        wait_for_scan_to_finish('host', 'token', False, version_id)

        # then
        verify(api).get('SecureDesigner/api/v1/scans')

    def test_wait_for_scan_to_finish_continues_to_check_if_scan_is_running(self):
        # given
        version_id = '111a01c8-a8c4-408b-b198-7bdfd07f25d3'
        api = mock(spec=uleska_api.UleskaApi)
        response1 = mock(spec=requests.Response)
        response1.text = "[{\"versionId\": \"111a01c8-a8c4-408b-b198-7bdfd07f25d3\"}]"
        response2 = mock(spec=requests.Response)
        response2.text = "[]"
        when(uleska_api).get_api(any, any).thenReturn(api)
        when(api).get('SecureDesigner/api/v1/scans').thenReturn(response1, response2)

        # when
        wait_for_scan_to_finish('host', 'token', False, version_id)

        # then
        verify(api, 2).get('SecureDesigner/api/v1/scans')

    def test_wait_for_scan_to_finish_throws_error_if_invalid_json(self):
        # given
        version_id = '111a01c8-a8c4-408b-b198-7bdfd07f25d3'
        api = mock(spec=uleska_api.UleskaApi)
        response = mock(spec=requests.Response)
        response.text = "Invalid Json"
        when(uleska_api).get_api(any, any).thenReturn(api)
        when(api).get('SecureDesigner/api/v1/scans').thenReturn(response)

        # when
        with self.assertRaises(SystemExit) as cm:
            wait_for_scan_to_finish('host', 'token', False, version_id)

        # then
        self.assertEqual(cm.exception.code, 2)