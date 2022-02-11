from unittest import TestCase
from uuid import UUID

import requests
from mockito import mock, when

from api import uleska_api
from service.toolkit import get_toolkit_id_from_name


class ToolkitTest(TestCase):

    def test_get_toolkit_id_from_name(self):
        # given
        toolkit_id = UUID('{d051653a-0999-4dbb-b4c8-9c326abdac6d}')
        toolkit_name = "Test Toolkit"
        toolkit_description = "Description"
        json = [{
            'toolkit': {
                'id': toolkit_id,
                'name': toolkit_name,
                'description': toolkit_description,
                'uleskaApproved': True,
                'customerId': None
            },
            'tools': []
        }]
        api = mock(spec=uleska_api.UleskaApi)
        response = mock(spec=requests.Response)
        when(uleska_api).get_api(any, any).thenReturn(api)
        when(api).get('SecureDesigner/api/v1/toolkits').thenReturn(response)
        when(response).json().thenReturn(json)

        # when
        result: str = get_toolkit_id_from_name('host', 'token', toolkit_name, False)

        # then
        self.assertEqual(toolkit_id, result)


    def test_get_toolkit_id_from_name_throws_value_error_if_no_match(self):
        # given
        toolkit_id = UUID('{d051653a-0999-4dbb-b4c8-9c326abdac6d}')
        toolkit_name = "Test Toolkit"
        toolkit_description = "Description"
        json = [{
            'toolkit': {
                'id': toolkit_id,
                'name': "Different Name",
                'description': toolkit_description,
                'uleskaApproved': True,
                'customerId': None
            },
            'tools': []
        }]
        api = mock(spec=uleska_api.UleskaApi)
        response = mock(spec=requests.Response)
        when(uleska_api).get_api(any, any).thenReturn(api)
        when(api).get('SecureDesigner/api/v1/toolkits').thenReturn(response)
        when(response).json().thenReturn(json)
        error_thrown = False

        # when
        try:
            get_toolkit_id_from_name('host', 'token', toolkit_name, False)
        except ValueError:
            error_thrown = True

        # then
        self.assertTrue(error_thrown)
