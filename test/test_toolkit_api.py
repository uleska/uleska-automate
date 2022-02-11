from unittest import TestCase
from mockito import when, mock
import requests
from uuid import UUID

from api import uleska_api
from api.toolkit_api import get_toolkits
from model.toolkit import Toolkit


class ToolkitApiTest(TestCase):

    def test_get_toolkits_returns_toolkits_and_tools(self):
        # given
        toolkit_id = UUID('{d051653a-0999-4dbb-b4c8-9c326abdac6d}')
        toolkit_name = "Test Toolkit"
        toolkit_description = "Description"

        expected_toolkit = Toolkit(toolkit_id, toolkit_name, toolkit_description, True, None)
        expected_tools = []
        json = [{
            'toolkit': {
            'id' : toolkit_id,
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
        results: dict = get_toolkits('host', 'token')

        # then
        self.assertTrue(len(results) == 1)
        self.assertEqual(expected_toolkit, results[0].toolkit)
        self.assertEqual(expected_tools, results[0].tools)


    def test_get_toolkits_returns_multiple_toolkits_and_tools(self):
        # given
        toolkit_id_1 = UUID('{d051653a-0999-4dbb-b4c8-9c326abdac6d}')
        toolkit_id_2 = UUID('{8eda1ccf-8e3f-424a-9dca-8d3783600355}')
        toolkit_name = "Test Toolkit"
        toolkit_description = "Description"

        expected_toolkit_1 = Toolkit(toolkit_id_1, toolkit_name, toolkit_description, True, None)
        expected_toolkit_2 = Toolkit(toolkit_id_2, toolkit_name, toolkit_description, True, None)
        expected_tools = []
        json = [{
            'toolkit': {
                'id': toolkit_id_1,
                'name': toolkit_name,
                'description': toolkit_description,
                'uleskaApproved': True,
                'customerId': None
            },
            'tools': []
        },
            {
                'toolkit': {
                    'id': toolkit_id_2,
                    'name': toolkit_name,
                    'description': toolkit_description,
                    'uleskaApproved': True,
                    'customerId': None
                },
                'tools': []
            }
        ]
        api = mock(spec=uleska_api.UleskaApi)
        response = mock(spec=requests.Response)
        when(uleska_api).get_api(any, any).thenReturn(api)
        when(api).get('SecureDesigner/api/v1/toolkits').thenReturn(response)
        when(response).json().thenReturn(json)

        # when
        results: dict = get_toolkits('host', 'token')

        # then
        self.assertTrue(len(results) == 2)
        self.assertEqual(expected_toolkit_1, results[0].toolkit)
        self.assertEqual(expected_toolkit_2, results[1].toolkit)
        self.assertEqual(expected_tools, results[0].tools)
        self.assertEqual(expected_tools, results[1].tools)